<?php
/**
 * Pest test bootstrap.
 *
 * Boots a fresh Craft console application against the dedicated test
 * database (DDEV's `db_test`) and installs the password-policy plugin so
 * every Integration test sees a clean schema. Runs once per test process —
 * subsequent tests reuse the same Craft instance and rely on per-test
 * transaction wrapping (see `tests/TestCase.php`) for state isolation.
 *
 * Custom bootstrap rather than `craft\test\TestCase` (Codeception) because
 * the project trades tighter coupling for a lighter dependency surface and
 * faster suite startup. We can't even reuse `craft\test\TestSetup` here —
 * it autoloads `craft\test\Craft`, which extends `Codeception\Module\Yii2`
 * and would force a Codeception dep we explicitly don't want. The bits
 * below replicate the parts of `TestSetup::configureCraft()` and
 * `createTestCraftObjectConfig()` we need (path constants, alias setup,
 * Yii2 + Craft.php require, app config merge), then construct the console
 * application directly.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use craft\config\GeneralConfig;
use craft\console\Application as ConsoleApplication;
use craft\db\Connection;
use craft\errors\InvalidPluginException;
use craft\helpers\App;
use craft\helpers\ArrayHelper;
use craft\migrations\Install as CraftInstall;
use craft\models\Site;
use craft\services\Config;
use craftpulse\passwordpolicy\migrations\Install as PluginInstall;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Composer autoload
// =============================================================================

require dirname(__DIR__) . '/vendor/autoload.php';

// =============================================================================
// DB env-var pinning
//
// DDEV exports `CRAFT_DB_DATABASE=db` (the playground's primary schema) into
// the container shell. PHPUnit's `<env force="true"/>` calls `putenv()` and
// sets `$_ENV` — but it does NOT overwrite `$_SERVER`, which DDEV populated
// at process start. `craft\helpers\App::env()` checks `$_SERVER` BEFORE
// `getenv()`, so a force-set env var still loses to the DDEV-injected
// `$_SERVER` value. Pin the test-DB credentials here before any Craft code
// runs, so every downstream `App::env()` call resolves against `db_test`.
//
// Without this, Integration tests that touch the DB hit the playground's
// production schema — DESTRUCTIVE.
// =============================================================================

$dbEnvPins = [
    'CRAFT_DB_DRIVER' => 'mysql',
    'CRAFT_DB_SERVER' => 'db',
    'CRAFT_DB_PORT' => '3306',
    'CRAFT_DB_DATABASE' => 'db_test',
    'CRAFT_DB_USER' => 'db',
    'CRAFT_DB_PASSWORD' => 'db',
    'CRAFT_DB_TABLE_PREFIX' => '',
    'CRAFT_DB_SCHEMA' => 'public',
];

foreach ($dbEnvPins as $envKey => $envValue) {
    $_SERVER[$envKey] = $envValue;
    $_ENV[$envKey] = $envValue;
    putenv("{$envKey}={$envValue}");
}

// =============================================================================
// Path constants — mirror what TestSetup::configureCraft() expects so any
// Craft internals that reference them keep working
// =============================================================================

$pluginRoot = dirname(__DIR__);
$craftRoot = $pluginRoot . '/tests/_craft';
$craftSrcPath = $pluginRoot . '/vendor/craftcms/cms/src';
$craftLibPath = $pluginRoot . '/vendor/craftcms/cms/lib';

defined('CRAFT_TESTS_PATH') || define('CRAFT_TESTS_PATH', $pluginRoot . '/tests');
defined('CRAFT_CONFIG_PATH') || define('CRAFT_CONFIG_PATH', $craftRoot . '/config');
defined('CRAFT_MIGRATIONS_PATH') || define('CRAFT_MIGRATIONS_PATH', $craftRoot . '/migrations');
defined('CRAFT_STORAGE_PATH') || define('CRAFT_STORAGE_PATH', $craftRoot . '/storage');
defined('CRAFT_TEMPLATES_PATH') || define('CRAFT_TEMPLATES_PATH', $craftRoot . '/templates');
defined('CRAFT_TRANSLATIONS_PATH') || define('CRAFT_TRANSLATIONS_PATH', $craftRoot . '/translations');
defined('CRAFT_VENDOR_PATH') || define('CRAFT_VENDOR_PATH', $pluginRoot . '/vendor');
defined('CRAFT_ROOT_PATH') || define('CRAFT_ROOT_PATH', $craftRoot);

// `tests/_craft/storage/` is entirely gitignored (a fresh checkout has
// nothing under it but `.gitignore` itself) and only ever gets populated
// locally because a long history of prior local test runs left its
// subdirectories behind. Most Craft/Yii components lazily create their own
// runtime directories on first use, but `yii\web\AssetManager` does not —
// its `basePath` (`@root/storage/runtime/assets`, set in
// `tests/_craft/config/app.php` for `View::registerJs()` callers like CP
// element actions) must already exist or it throws `InvalidConfigException`.
// A bare CI checkout has no such history, so create it explicitly.
if (!is_dir(CRAFT_STORAGE_PATH . '/runtime/assets')) {
    mkdir(CRAFT_STORAGE_PATH . '/runtime/assets', 0777, true);
}

defined('YII_ENV') || define('YII_ENV', 'test');
defined('YII_DEBUG') || define('YII_DEBUG', true);
defined('CRAFT_ENVIRONMENT') || define('CRAFT_ENVIRONMENT', 'test');
defined('CURLOPT_TIMEOUT_MS') || define('CURLOPT_TIMEOUT_MS', 155);
defined('CURLOPT_CONNECTTIMEOUT_MS') || define('CURLOPT_CONNECTTIMEOUT_MS', 156);

// Force CLI request context — `craft\console\Application` requires it
$_SERVER['SCRIPT_FILENAME'] ??= 'craft';
$_SERVER['SCRIPT_NAME'] ??= 'craft';

// Prevent `headers already sent` interfering with PHPUnit output
if (PHP_SAPI !== 'cli') {
    ob_start();
}

// =============================================================================
// Yii + Craft globals — these aren't autoloaded; require them explicitly
// =============================================================================

require $craftLibPath . '/yii2/Yii.php';
require $craftSrcPath . '/Craft.php';

// =============================================================================
// Aliases
// =============================================================================

Craft::setAlias('@vendor', CRAFT_VENDOR_PATH);
Craft::setAlias('@craftcms', $pluginRoot . '/vendor/craftcms/cms');
Craft::setAlias('@lib', $craftLibPath);
Craft::setAlias('@appicons', $craftSrcPath . '/icons');
Craft::setAlias('@config', CRAFT_CONFIG_PATH);
Craft::setAlias('@contentMigrations', CRAFT_MIGRATIONS_PATH);
Craft::setAlias('@root', CRAFT_ROOT_PATH);
Craft::setAlias('@storage', CRAFT_STORAGE_PATH);
Craft::setAlias('@templates', CRAFT_TEMPLATES_PATH);
Craft::setAlias('@tests', CRAFT_TESTS_PATH);
Craft::setAlias('@translations', CRAFT_TRANSLATIONS_PATH);

// =============================================================================
// Build the Craft console application config
//
// Config service comes first — it knows how to read `tests/_craft/config/*.php`
// and overlay them on top of `craftcms/cms/src/config/app.php` defaults. The
// merged result is the constructor config for `craft\console\Application`.
// =============================================================================

$configService = new Config();
$configService->env = 'test';
$configService->configDir = CRAFT_CONFIG_PATH;
$configService->appDefaultsDir = $craftSrcPath . '/config/defaults';

$config = ArrayHelper::merge(
    [
        'components' => [
            'config' => $configService,
        ],
    ],
    require $craftSrcPath . '/config/app.php',
    require $craftSrcPath . '/config/app.console.php',
    $configService->getConfigFromFile('app'),
    $configService->getConfigFromFile('app.console'),
);

$config = ArrayHelper::merge($config, [
    'class' => ConsoleApplication::class,
    'id' => 'craft-test',
    'env' => 'test',
    'basePath' => $craftSrcPath,
    'vendorPath' => CRAFT_VENDOR_PATH,
]);

/** @var ConsoleApplication $app */
$app = Craft::createObject($config);

// =============================================================================
// Schema bootstrap — install Craft + the plugin if `db_test` is empty
//
// One-shot: a fresh `db_test` gets the full Craft install + plugin install.
// Re-runs find an already-installed schema and skip. Trades a slow first run
// for cheap subsequent runs — acceptable locally and predictable in CI when
// the test DB starts empty.
// =============================================================================

/** @var Connection $db */
$db = $app->getDb();
$db->open();

if (!$app->getIsInstalled(true)) {
    $migration = new CraftInstall([
        'db' => $db,
        'username' => 'pesttester',
        'password' => 'craftcms2024!!',
        'email' => 'tests@craftpulse.com',
        'site' => new Site([
            'name' => 'Password Policy Test Site',
            'handle' => 'default',
            'hasUrls' => true,
            'baseUrl' => App::env('PRIMARY_SITE_URL') ?: 'https://test.craftcms.test/',
            'language' => 'en-US',
            'primary' => true,
        ]),
    ]);

    if (!$migration->up(true)) {
        throw new RuntimeException('Failed to install Craft into the test database.');
    }

    // Re-run setIsInstalled() detection so getPlugins() returns a working
    // service against the freshly populated info table.
    $app->getIsInstalled(true);
}

// =============================================================================
// Plugin install — register + install the password-policy plugin so its
// schema and services are available to every Integration test
// =============================================================================

$plugins = $app->getPlugins();

// Audit Kit is a hard dependency (composer `require`) — the shared hash-chain
// engine + the dispatch Bus PP emits governance events onto live in it. It ships
// no tables/migrations, so installing it just runs its init() (sets
// `AuditKit::$plugin`, registers the Bus + EventTypes components). Install it
// first so PP's own install sees its dependency satisfied.
if (!$plugins->isPluginInstalled('audit-kit')) {
    try {
        $plugins->installPlugin('audit-kit');
    } catch (InvalidPluginException) {
        // Path-repo composer install may not surface the plugin to
        // getPluginInfo() until a rescan; audit-kit has no schema to land, so a
        // failed install here is non-fatal — the runtime instance below covers
        // the services PP needs.
    }
}

if (!$plugins->isPluginInstalled('password-policy')) {
    try {
        $plugins->installPlugin('password-policy');
    } catch (InvalidPluginException) {
        // Path-repo composer install in vendor/ may not surface to
        // Plugins::getPluginInfo() until a composer rescan. Fall back to a
        // direct migration up against the plugin's Install class so the
        // schema lands regardless.
        (new PluginInstall())->up(true);
    }
}

// Reload `PasswordPolicy::$plugin` in case the plugin's `init()` ran before
// `Plugins::loadPlugins()` finished registering services. Defensive — every
// downstream test trusts `PasswordPolicy::$plugin` to be live.
PasswordPolicy::$plugin ?? PasswordPolicy::getInstance();
