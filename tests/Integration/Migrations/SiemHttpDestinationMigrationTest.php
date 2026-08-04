<?php
/**
 * Pest coverage for `m260804_165223_AddHttpDestinationToSiemForwarders`.
 *
 * Two things are pinned:
 *
 *  - The migration adds all five columns the HTTP destination and the
 *    syslog framing need, on a table that predates them.
 *  - It is idempotent. `migrations.md` requires every migration in this
 *    plugin to be safe to re-run, and this one is guarded per column
 *    rather than per table, so the guards are what the second run
 *    exercises.
 *
 * The test drops the five columns to reach the pre-migration shape, then
 * runs `safeUp()` — which is also what restores the schema, since
 * `MigrationTestCase::restorePluginSchema()` cannot: `Install`'s
 * `_createSiemForwardersTable()` is guarded by `tableExists`, and this
 * test leaves the table in place. `afterEach` re-runs `safeUp()`
 * unconditionally so a mid-test failure can't leave `db_test` short a
 * column for the next test class.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\migrations\m260804_165223_AddHttpDestinationToSiemForwarders;

// =============================================================================
// Setup
// =============================================================================

/**
 * Every column the migration is responsible for.
 */
const SIEM_HTTP_COLUMNS = ['url', 'authType', 'authToken', 'headers', 'framing'];

const SIEM_FORWARDERS_TABLE = '{{%passwordpolicy_siem_forwarders}}';

beforeEach(function() {
    Craft::$app->getDb()->createCommand()
        ->delete(SIEM_FORWARDERS_TABLE)
        ->execute();
});

afterEach(function() {
    // Idempotent, so this is a no-op on the happy path and a repair on a
    // failed one.
    (new m260804_165223_AddHttpDestinationToSiemForwarders())->safeUp();
    Craft::$app->getDb()->getSchema()->refresh();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the forwarder table's column names, read fresh from the DB.
 *
 * @return string[]
 */
function siemForwarderColumnNames(): array
{
    $schema = Craft::$app->getDb()->getTableSchema(SIEM_FORWARDERS_TABLE, true);

    return $schema !== null ? array_keys($schema->columns) : [];
}

/**
 * Drops the five columns the migration owns, leaving the table in its
 * pre-migration shape.
 */
function dropSiemHttpColumns(): void
{
    $db = Craft::$app->getDb();

    foreach (SIEM_HTTP_COLUMNS as $column) {
        $db->createCommand()
            ->dropColumn(SIEM_FORWARDERS_TABLE, $column)
            ->execute();
    }

    $db->getSchema()->refresh();
}

// =============================================================================
// The add path
// =============================================================================

it('adds every HTTP destination column to a table that predates them', function() {
    dropSiemHttpColumns();

    expect(siemForwarderColumnNames())->not->toContain(...SIEM_HTTP_COLUMNS);

    expect((new m260804_165223_AddHttpDestinationToSiemForwarders())->safeUp())->toBeTrue();

    expect(siemForwarderColumnNames())->toContain(...SIEM_HTTP_COLUMNS);
});

it('leaves the syslog address nullable so an HTTP forwarder can omit it', function() {
    (new m260804_165223_AddHttpDestinationToSiemForwarders())->safeUp();

    $schema = Craft::$app->getDb()->getTableSchema(SIEM_FORWARDERS_TABLE, true);

    expect($schema?->getColumn('host')?->allowNull)->toBeTrue()
        ->and($schema?->getColumn('port')?->allowNull)->toBeTrue()
        ->and($schema?->getColumn('url')?->allowNull)->toBeTrue();
});

it('defaults framing to the RFC 5425 octet-counted value', function() {
    dropSiemHttpColumns();
    (new m260804_165223_AddHttpDestinationToSiemForwarders())->safeUp();

    $schema = Craft::$app->getDb()->getTableSchema(SIEM_FORWARDERS_TABLE, true);
    $framing = $schema?->getColumn('framing');

    expect($framing?->allowNull)->toBeFalse()
        ->and($framing?->defaultValue)->toBe('octet-counted');
});

// =============================================================================
// Idempotency
// =============================================================================

it('is a no-op on a second run', function() {
    $migration = new m260804_165223_AddHttpDestinationToSiemForwarders();

    dropSiemHttpColumns();
    $migration->safeUp();

    $afterFirstRun = siemForwarderColumnNames();

    // The guards are per column, so the second run walks every one of them
    // and must add nothing.
    expect($migration->safeUp())->toBeTrue()
        ->and(siemForwarderColumnNames())->toBe($afterFirstRun);
});

it('is a no-op on an already-current schema', function() {
    // The state an operator's `migrate/all` re-run actually hits: nothing
    // dropped, every column present.
    $migration = new m260804_165223_AddHttpDestinationToSiemForwarders();
    $before = siemForwarderColumnNames();

    expect($migration->safeUp())->toBeTrue()
        ->and(siemForwarderColumnNames())->toBe($before);
});

// =============================================================================
// Rows survive
// =============================================================================

it('keeps existing forwarder rows through the column adds', function() {
    $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

    dropSiemHttpColumns();

    Craft::$app->getDb()->createCommand()
        ->insert(SIEM_FORWARDERS_TABLE, [
            'name' => 'pre-existing',
            'protocol' => 'syslog-tls',
            'host' => 'siem.example.test',
            'port' => 6514,
            'enabled' => true,
            'consecutiveFailures' => 0,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => '11111111-2222-3333-4444-555555555555',
        ])
        ->execute();

    (new m260804_165223_AddHttpDestinationToSiemForwarders())->safeUp();

    $row = (new craft\db\Query())
        ->from(SIEM_FORWARDERS_TABLE)
        ->where(['uid' => '11111111-2222-3333-4444-555555555555'])
        ->one();

    expect($row)->not->toBeNull()
        ->and($row['host'])->toBe('siem.example.test')
        // Every row lands on the conformant framing. The forwarder surface
        // has never shipped, so there is no configured receiver anywhere
        // that a change of framing could break.
        ->and($row['framing'])->toBe('octet-counted')
        ->and($row['authType'])->toBe('none')
        ->and($row['url'])->toBeNull();
});
