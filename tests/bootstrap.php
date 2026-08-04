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
 * @link      https://craft-pulse.com
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
use craftpulse\auditkit\AuditKit;
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
//
// The connection COORDINATES (driver, host, port) are overridable through
// `PP_TEST_DB_*` process env vars, defaulting to the DDEV MySQL container. The
// prefix is deliberately distinct from `CRAFT_DB_*`: those are the vars DDEV
// injects and that this block exists to defeat, so reading a default from them
// would reintroduce the bug. The schema NAME stays hard-pinned, because
// `db_test` is what makes the suite non-destructive and that must not depend on
// the environment being set correctly.
//
// The override exists so the same suite can run against PostgreSQL in CI:
// `README.md` advertises PostgreSQL 13+, and the absence of a PostgreSQL leg is
// why two migrations that abort on that driver shipped unnoticed.
// =============================================================================

$dbEnvPins = [
    'CRAFT_DB_DRIVER' => getenv('PP_TEST_DB_DRIVER') ?: 'mysql',
    'CRAFT_DB_SERVER' => getenv('PP_TEST_DB_SERVER') ?: 'db',
    'CRAFT_DB_PORT' => getenv('PP_TEST_DB_PORT') ?: '3306',
    'CRAFT_DB_DATABASE' => 'db_test',
    'CRAFT_DB_USER' => getenv('PP_TEST_DB_USER') ?: 'db',
    'CRAFT_DB_PASSWORD' => getenv('PP_TEST_DB_PASSWORD') ?: 'db',
    'CRAFT_DB_TABLE_PREFIX' => '',
    'CRAFT_DB_SCHEMA' => getenv('PP_TEST_DB_SCHEMA') ?: 'public',
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
// Project config YAML writing is off for the whole process
//
// Every project config write the suite makes belongs to `db_test` and rolls back
// with the per-test transaction. A YAML write does not: it clears
// `tests/_craft/config/project/` and regenerates the whole tree on disk, which
// no transaction undoes and which leaves untracked files behind in the repo.
// `ProjectConfig::flush()` reaches `writeYamlFiles()` whenever a `set()` marked
// the YAML dirty — which the Audit Kit adoption helper deliberately does, and
// which any future forced write would too.
// =============================================================================

$app->getProjectConfig()->writeYamlAutomatically = false;

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
        'email' => 'tests@craft-pulse.com',
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
// Audit Kit module registration
//
// Audit Kit is a hard dependency (composer `require`) — the shared hash-chain
// engine, the runtime event-type registry, and the dispatch Bus PP emits
// governance events onto all live in it. Since 1.1.0 it ships as a
// library-shipped Yii module (`type: library`) rather than a Craft plugin, so
// Craft cannot discover it and `installPlugin('audit-kit')` now throws
// `InvalidPluginException`. Registering the module is what makes the bus exist.
//
// Registered here, ahead of the plugin install below, for two reasons: PP's
// `Install` migration pumps the kit migrator, and a bootstrap that reached the
// plugin install without the module attached would fail there rather than
// producing a usable suite. It is idempotent, and PP's own `init()` registers it
// too — that call is the production path and the one
// `tests/Unit/AuditKitRetrofitTest.php` guards with a token scan, because this
// bootstrap call would otherwise mask its absence.
// =============================================================================

AuditKit::register();

// =============================================================================
// Plugin install — register + install the password-policy plugin so its
// schema and services are available to every Integration test
// =============================================================================

$plugins = $app->getPlugins();

if (!$plugins->isPluginInstalled('password-policy')) {
    try {
        $plugins->installPlugin('password-policy');
    } catch (InvalidPluginException $e) {
        // `craftcms/plugin-installer` writes the ROOT package into
        // `vendor/craftcms/plugins.php`, so on both a local
        // `composer install` in the plugin directory and the CI job this path is
        // not normally reached. It survives as a fallback for a vendor tree
        // whose plugin map is stale, and it now fails loudly: a silently
        // half-applied schema produced downstream fatals rather than a failing
        // test, which is precisely how a broken Audit Kit retrofit stayed
        // invisible.
        if (!(new PluginInstall())->up(true)) {
            throw new RuntimeException(
                'Failed to install the password-policy plugin into the test database. '
                . 'installPlugin() reported: ' . $e->getMessage(),
                previous: $e,
            );
        }
    }
}

// Reload `PasswordPolicy::$plugin` in case the plugin's `init()` ran before
// `Plugins::loadPlugins()` finished registering services. Defensive — every
// downstream test trusts `PasswordPolicy::$plugin` to be live.
PasswordPolicy::$plugin ?? PasswordPolicy::getInstance();

// =============================================================================
// Pending plugin migrations
//
// The install block above only fires on an EMPTY database. A `db_test` carried
// over from an earlier schema version therefore keeps its old columns, and every
// Integration test then runs against them — which surfaces as
// `UnknownPropertyException: Setting unknown property …Record::<newColumn>`
// from whichever test touches the record first, rather than as a schema error
// naming the cause. Applying the pending chain here keeps a long-lived local
// test database on the same schema CI gets from a fresh install.
//
// No-op on a fresh install (`installPlugin()` records the whole chain) and on an
// already-current database.
//
// It does NOT rescue one specific broken state: a `db_test` whose `plugins` row
// is gone but whose tables remain. `installPlugin()` then runs `Install`, every
// `_create*Table()` returns early on the tables that still exist, and the whole
// migration chain is recorded as applied without running — so a column added by
// a dated migration is missing and nothing will ever add it. Drop and recreate
// `db_test`; the next run reinstalls from scratch, which is what CI does anyway.
// =============================================================================

$migrator = PasswordPolicy::$plugin?->getMigrator();

if ($migrator !== null && $migrator->getNewMigrations() !== []) {
    $migrator->up();
    $db->getSchema()->refresh();
}

// =============================================================================
// Fail-fast harness assertions
//
// Both of these were reachable-but-unasserted, and both surfaced downstream as a
// fatal inside an unrelated test rather than as a bootstrap failure naming the
// cause. `AuditKit::$plugin` in particular is a typed static with no default:
// reading it before the module is registered throws
// `Error: Typed static property ... must not be accessed before initialization`
// from whichever test happens to touch it first.
// =============================================================================

if (!(Craft::$app->getModule(AuditKit::ID) instanceof AuditKit)) {
    throw new RuntimeException(
        'The Audit Kit module is not attached to the test application. Every '
        . 'governance emission and every hash-chain write depends on it.',
    );
}

if (PasswordPolicy::$plugin === null) {
    throw new RuntimeException(
        'The password-policy plugin did not boot in the test application. Every '
        . 'Integration test resolves its services through PasswordPolicy::$plugin.',
    );
}
