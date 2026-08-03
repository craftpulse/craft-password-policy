<?php
/**
 * Pest coverage for `m260803_151359_AdoptAuditKitModule`, the migration that
 * sheds the plugin-era Audit Kit registration.
 *
 * Audit Kit 1.0.x shipped as a Craft plugin; 1.1.0 ships the same package as a
 * library-shipped Yii module, which Craft cannot discover. That strands three
 * things on any install that carried the plugin era: migration history on the
 * `plugin:audit-kit` track, the `plugins.audit-kit` project config entry, and the
 * `audit-kit` row in the `plugins` table. The migration delegates all of it to
 * the kit's own `PluginAdoption::adopt()`.
 *
 * Three properties are asserted, because all three are load-bearing for a
 * migration that ships to installs in every possible starting state:
 *
 *  1. **It adopts.** Plugin-era history is re-tracked onto `module:audit-kit`
 *     (minus the synthetic `Install` row, which names no migration class on the
 *     module track), and both registrations are removed.
 *  2. **It is idempotent.** Every consumer in the estate ships the same
 *     one-liner and several may run it on one install, so a second run must
 *     converge rather than duplicate or fail.
 *  3. **It is a clean no-op on an install that never had the plugin**, including
 *     every fresh 5.2.0 install. Nothing is written and nothing throws.
 *
 * Isolation: this test lives outside `Integration/Migrations` on purpose. That
 * folder is bound to the non-transactional `MigrationTestCase`, which drops and
 * rebuilds the whole plugin schema around every test; the adoption migration does
 * no DDL and touches only the `migrations` and `plugins` tables and project
 * config, so the standard transaction wrap is both correct and far cheaper. The
 * project config write is flushed by the kit helper, so `afterEach` resets the
 * service to resync its in-memory state with the rolled-back rows.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use craft\services\ProjectConfig;
use craftpulse\auditkit\helpers\PluginAdoption;
use craftpulse\passwordpolicy\migrations\m260803_151359_AdoptAuditKitModule;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the migration history names recorded against the given track.
 *
 * @return list<string>
 */
function ppAdoptionHistory(string $track): array
{
    return (new Query())
        ->select(['name'])
        ->from(CraftTable::MIGRATIONS)
        ->where(['track' => $track])
        ->orderBy(['name' => SORT_ASC])
        ->column(Craft::$app->getDb());
}

/**
 * Whether a `plugins` row exists for the plugin-era Audit Kit handle.
 */
function ppAdoptionPluginRowExists(): bool
{
    return (new Query())
        ->from(CraftTable::PLUGINS)
        ->where(['handle' => PluginAdoption::PLUGIN_HANDLE])
        ->exists(Craft::$app->getDb());
}

/**
 * Whether the plugin-era project config entry is present, in either the loaded
 * or the external config.
 */
function ppAdoptionProjectConfigEntryExists(): bool
{
    $projectConfig = Craft::$app->getProjectConfig();
    $path = ProjectConfig::PATH_PLUGINS . '.' . PluginAdoption::PLUGIN_HANDLE;

    return $projectConfig->get($path) !== null || $projectConfig->get($path, true) !== null;
}

/**
 * Seeds a full plugin-era Audit Kit registration: the `plugins` row, the
 * synthetic `Install` history row plus one named migration on the plugin track,
 * and the project config entry.
 *
 * Mirrors what `Plugins::installPlugin('audit-kit')` left behind under 1.0.x. The
 * named migration is fictional on purpose: the kit shipped none, and the point is
 * to prove a real name is carried onto the module track while `Install` is not.
 */
function ppAdoptionSeedPluginEra(string $namedMigration): void
{
    $db = Craft::$app->getDb();
    $projectConfig = Craft::$app->getProjectConfig();
    $now = Db::prepareDateForDb(new DateTimeImmutable());

    Db::insert(CraftTable::PLUGINS, [
        'handle' => PluginAdoption::PLUGIN_HANDLE,
        'version' => '1.0.1',
        'schemaVersion' => '1.0.0',
        'installDate' => $now,
    ], $db);

    foreach (['Install', $namedMigration] as $name) {
        Db::insert(CraftTable::MIGRATIONS, [
            'track' => PluginAdoption::PLUGIN_TRACK,
            'name' => $name,
            'applyTime' => $now,
        ], $db);
    }

    $muteEvents = $projectConfig->muteEvents;
    $projectConfig->muteEvents = true;

    try {
        $projectConfig->set(
            ProjectConfig::PATH_PLUGINS . '.' . PluginAdoption::PLUGIN_HANDLE,
            ['edition' => 'standard', 'enabled' => true, 'schemaVersion' => '1.0.0'],
        );
    } finally {
        $projectConfig->muteEvents = $muteEvents;
    }
}

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->migration = new m260803_151359_AdoptAuditKitModule();

    $projectConfig = Craft::$app->getProjectConfig();
    $db = Craft::$app->getDb();

    // The previous test's `flush()` was rolled back with its transaction, so the
    // service's in-memory working config is ahead of the restored rows. Re-read
    // it before arranging anything.
    $projectConfig->reset();

    // `saveModifiedConfigData()` rerolls `info.configVersion` and Craft memoizes
    // the `Info` model, so the rollback leaves the in-memory version ahead of the
    // stored one and `_acquireLock()` then rejects every later write with
    // `StaleResourceException` — in this file and in every file that runs after
    // it. Capture the stored value and put it back in `afterEach`.
    $this->configVersion = Craft::$app->getInfo()->configVersion;

    // `db_test` may already carry a plugin-era registration from before the
    // retrofit. Clear all three parts so each case arranges its own starting
    // state; the transaction wrap restores whatever was there. The project config
    // removal deliberately does NOT flush: `set()` commits to the loaded working
    // config only, which is all the assertions read, and flushing here would be
    // the very write under test.
    Db::delete(CraftTable::PLUGINS, ['handle' => PluginAdoption::PLUGIN_HANDLE], db: $db);
    Db::delete(
        CraftTable::MIGRATIONS,
        ['track' => [PluginAdoption::PLUGIN_TRACK, PluginAdoption::MODULE_TRACK]],
        db: $db,
    );

    $muteEvents = $projectConfig->muteEvents;
    $projectConfig->muteEvents = true;

    try {
        $projectConfig->set(
            ProjectConfig::PATH_PLUGINS . '.' . PluginAdoption::PLUGIN_HANDLE,
            null,
            force: true,
        );
    } finally {
        $projectConfig->muteEvents = $muteEvents;
    }
});

afterEach(function() {
    Craft::$app->getInfo()->configVersion = $this->configVersion;
});

// =============================================================================
// It adopts a plugin-era registration
// =============================================================================

it('sheds the plugin-era registration and re-tracks its migration history', function() {
    $namedMigration = 'm260101_000000_' . StringHelper::randomString(8);

    ppAdoptionSeedPluginEra($namedMigration);

    expect(ppAdoptionPluginRowExists())->toBeTrue();
    expect(ppAdoptionProjectConfigEntryExists())->toBeTrue();

    expect($this->migration->safeUp())->toBeTrue();

    expect(ppAdoptionPluginRowExists())->toBeFalse(
        'The plugins-table row must be gone: Craft can no longer resolve the package.',
    );
    expect(ppAdoptionProjectConfigEntryExists())->toBeFalse(
        'The project config entry must be gone, or the next external apply treats '
        . 'the kit as a plugin that still needs installing.',
    );
    expect(ppAdoptionHistory(PluginAdoption::PLUGIN_TRACK))->toBe([]);
    expect(ppAdoptionHistory(PluginAdoption::MODULE_TRACK))->toBe(
        [$namedMigration],
        'The named plugin-era migration must carry onto the module track so the '
        . 'module migrator never re-runs it, while the synthetic Install row is '
        . 'dropped rather than copied.',
    );
});

// =============================================================================
// It is idempotent
// =============================================================================

it('converges on a second run rather than duplicating or failing', function() {
    $namedMigration = 'm260101_000000_' . StringHelper::randomString(8);

    ppAdoptionSeedPluginEra($namedMigration);

    expect($this->migration->safeUp())->toBeTrue();

    $afterFirstRun = ppAdoptionHistory(PluginAdoption::MODULE_TRACK);

    expect($this->migration->safeUp())->toBeTrue();

    expect(ppAdoptionHistory(PluginAdoption::MODULE_TRACK))->toBe(
        $afterFirstRun,
        'A second run must not duplicate the adopted history row. Every consumer '
        . 'ships this same one-liner and several may run it on one install.',
    );
    expect(ppAdoptionHistory(PluginAdoption::PLUGIN_TRACK))->toBe([]);
    expect(ppAdoptionPluginRowExists())->toBeFalse();
    expect(ppAdoptionProjectConfigEntryExists())->toBeFalse();
});

// =============================================================================
// It is a clean no-op on an install that never had the plugin
// =============================================================================

it('writes nothing on an install that never carried the plugin', function() {
    // `beforeEach` already cleared both registrations, so this is the fresh-install
    // shape: no plugins row, no plugin-track history, no project config entry.
    expect(ppAdoptionPluginRowExists())->toBeFalse();
    expect(ppAdoptionProjectConfigEntryExists())->toBeFalse();

    $pluginCountBefore = (new Query())->from(CraftTable::PLUGINS)->count('*', Craft::$app->getDb());

    expect($this->migration->safeUp())->toBeTrue();

    expect(ppAdoptionHistory(PluginAdoption::MODULE_TRACK))->toBe(
        [],
        'Nothing may be written onto the module track when there was no plugin-era '
        . 'history to adopt.',
    );
    expect(ppAdoptionHistory(PluginAdoption::PLUGIN_TRACK))->toBe([]);
    expect((new Query())->from(CraftTable::PLUGINS)->count('*', Craft::$app->getDb()))
        ->toBe($pluginCountBefore, 'No other plugin registration may be touched.');
});

// =============================================================================
// It is irreversible
// =============================================================================

it('refuses to revert', function() {
    // Reinstating a plugin registration for a package that is no longer a plugin
    // is not a state worth being able to return to.
    ob_start();
    $reverted = $this->migration->safeDown();
    $output = (string)ob_get_clean();

    expect($reverted)->toBeFalse();
    expect($output)->toContain('cannot be reverted');
});
