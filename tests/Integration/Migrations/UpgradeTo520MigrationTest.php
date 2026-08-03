<?php
/**
 * Pest coverage for the 5.1.1 → 5.2.0 upgrade migration chain.
 *
 * Pins T1.2 (upgrade migration seeds password history) and TX.2 (zero
 * behavior change on 5.1.1 upgrade) — both deferred from manual testing
 * because the by-hand fixturing approach (uninstall, manually inject
 * `pwned` keys, mark migrations not-applied, run craft up) was too
 * fragile to repeat reliably.
 *
 * Approach: in-test setup tears the plugin schema down to a 5.1.1-shaped
 * state (no plugin tables, no plugin migration history rows), seeds
 * 5.1.1-era project config keys (`pwned`, `pwnedFailMode`, `groupPolicies`),
 * then drives the migrator forward. Each test asserts on a single facet
 * of the post-upgrade state.
 *
 * Tests run outside the standard transaction wrapper because DDL is
 * auto-committed in MySQL/MariaDB and can't roll back. The
 * {@see MigrationTestCase} base restores the 5.2.0 schema in `tearDown`
 * so adjacent tests see a clean baseline.
 *
 * Every test that asserts on the password-history seed OWNS the users it
 * counts: `MigrationTestCase::seedFixtureUser()` writes a user row with an
 * explicit `password` value (bcrypt hash, `null`, or `''`) and the base class
 * deletes it in `tearDown`. Assertions compare the seeded `userId` set against
 * the set of users matching the migration's own filter, so nothing here
 * depends on how many users the bootstrap, a sibling test, or a previous suite
 * run happened to leave in `db_test`.
 *
 * Count assertions cast through `(int)` on purpose. `craft\db\Query::count()`
 * inherits Yii's `@return int|string|null` contract ("may be a string
 * depending on the underlying database engine"), and PDO/MySQL returns the
 * string `'1'` here. Asserting on the cast value pins the number rather than
 * the driver's scalar type.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Connection;
use craft\db\Query;
use craft\db\Table as CraftTable;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\MigrationTestCase;

// =============================================================================
// Setup — fabricate a 5.1.1-shaped state at the start of every test
// =============================================================================

beforeEach(function() {
    /** @var MigrationTestCase $this */
    $this->tearDownPluginSchema();
});

// =============================================================================
// Helpers — local closures over the test's Craft instance
// =============================================================================

/**
 * Runs every pending plugin migration via the live migrator. No-op when
 * the migrator queue is already empty (defensive — every test in this
 * file calls `tearDownPluginSchema()` first, but a future maintainer
 * adding a regression test that doesn't tear down should still get a
 * sane no-op here).
 */
function runPendingPluginMigrations(): void
{
    $migrator = PasswordPolicy::$plugin->getMigrator();

    if (empty($migrator->getNewMigrations())) {
        return;
    }

    $migrator->up();
}

/**
 * Plants legacy 5.1.1-era keys into the plugin's project config slot.
 * Wraps in muteEvents to mirror production rename safety.
 *
 * @param array<string, mixed> $legacyKeys
 */
function plantLegacyProjectConfig(array $legacyKeys): void
{
    $projectConfig = Craft::$app->getProjectConfig();
    $current = $projectConfig->get('plugins.password-policy.settings') ?? [];
    $merged = array_merge($current, $legacyKeys);

    $wasMuted = $projectConfig->muteEvents;
    $projectConfig->muteEvents = true;

    try {
        $projectConfig->set('plugins.password-policy.settings', $merged);
    } finally {
        $projectConfig->muteEvents = $wasMuted;
    }
}

/**
 * Reads back the plugin's project config settings as a raw array. Used
 * to verify rename-and-drop behavior without invoking the SettingsModel
 * alias layer (which would mask the rename by reading legacy keys via
 * `__get` from the canonical attribute).
 */
function readPluginProjectConfig(): array
{
    return Craft::$app->getProjectConfig()->get('plugins.password-policy.settings') ?? [];
}

/**
 * Returns the value that scopes an information_schema lookup to the current
 * connection: the database name on MySQL, the namespace on PostgreSQL. Mirrors
 * `m260513_142613_DeduplicateElementTableForeignKeys::_informationSchemaScope()`.
 */
function migrationSchemaScope(): string
{
    $db = Craft::$app->getDb();

    return $db->getDriverName() === Connection::DRIVER_PGSQL
        ? (string)$db->createCommand('SELECT current_schema()')->queryScalar()
        : (string)$db->createCommand('SELECT DATABASE()')->queryScalar();
}

/**
 * Returns the `ON DELETE` rule of the foreign key on `$table.$column`.
 *
 * Reads the ANSI `referential_constraints` and `key_column_usage` views, both
 * present on MySQL and PostgreSQL, in lowercase: PostgreSQL's catalog columns
 * are genuinely lowercase and Yii quotes whatever it is handed, so the
 * uppercase form this replaced was a hard error there rather than a
 * case-insensitive match. `delete_rule` spells the rules identically on both
 * engines ("CASCADE", "SET NULL", "NO ACTION").
 */
function foreignKeyDeleteRule(string $table, string $column): ?string
{
    $rule = (new Query())
        ->select(['rc.delete_rule'])
        ->from(['rc' => 'information_schema.referential_constraints'])
        ->innerJoin(
            ['kcu' => 'information_schema.key_column_usage'],
            '[[rc.constraint_name]] = [[kcu.constraint_name]]'
            . ' AND [[rc.constraint_schema]] = [[kcu.constraint_schema]]',
        )
        ->where([
            'rc.constraint_schema' => migrationSchemaScope(),
            'kcu.table_name' => Craft::$app->getDb()->getSchema()->getRawTableName($table),
            'kcu.column_name' => $column,
        ])
        ->scalar();

    return $rule === false ? null : (string)$rule;
}

/**
 * Returns whichever schema definition encodes `changeReason`'s closed list on
 * the current engine.
 *
 * Craft's `enum()` column builder lands a native `ENUM` type on MySQL and a
 * `varchar` plus a CHECK constraint on PostgreSQL. Both enforce the same closed
 * list, so a test that asserts the list should not care which mechanism carries
 * it; it reads the values out of the definition text either way.
 */
function changeReasonClosedListDefinition(): string
{
    $db = Craft::$app->getDb();
    $table = $db->getSchema()->getRawTableName('{{%passwordpolicy_password_history}}');

    if ($db->getDriverName() === Connection::DRIVER_PGSQL) {
        return (string)(new Query())
            ->select(['cc.check_clause'])
            ->from(['cc' => 'information_schema.check_constraints'])
            ->innerJoin(
                ['ccu' => 'information_schema.constraint_column_usage'],
                '[[cc.constraint_name]] = [[ccu.constraint_name]]'
                . ' AND [[cc.constraint_schema]] = [[ccu.constraint_schema]]',
            )
            ->where([
                'ccu.table_name' => $table,
                'ccu.column_name' => 'changeReason',
            ])
            ->scalar();
    }

    return (string)$db->getSchema()
        ->getTableSchema('{{%passwordpolicy_password_history}}', true)
        ->columns['changeReason']
        ->dbType;
}

/**
 * Bcrypt hash for a fixture user's `password` column. The seed copies the
 * column verbatim so any non-empty string would do, but hashing keeps the
 * fixture shaped like a real 5.1.1 row.
 */
function fixturePasswordHash(string $plaintext): string
{
    return Craft::$app->getSecurity()->hashPassword($plaintext);
}

/**
 * Element IDs of every user the migration's seed filter matches (`password`
 * neither NULL nor empty). Cast to int so the set compares cleanly against
 * the IDs `seedFixtureUser()` hands back.
 *
 * @return int[]
 */
function userIdsWithAStoredPassword(): array
{
    return array_map('intval', (new Query())
        ->select(['id'])
        ->from(CraftTable::USERS)
        ->where(['not', ['password' => null]])
        ->andWhere(['not', ['password' => '']])
        ->column());
}

/**
 * Element IDs carried by every row in the seeded password-history table.
 * Duplicates are preserved — "one row per user" is part of the contract.
 *
 * @return int[]
 */
function seededHistoryUserIds(): array
{
    return array_map('intval', (new Query())
        ->select(['userId'])
        ->from('{{%passwordpolicy_password_history}}')
        ->column());
}

// =============================================================================
// T1.2 — upgrade migration seeds password history
// =============================================================================

it('creates all eight plugin tables when migrating from 5.1.1', function() {
    expect(Craft::$app->getDb()->tableExists('{{%passwordpolicy_password_history}}'))->toBeFalse();

    runPendingPluginMigrations();

    $expected = [
        '{{%passwordpolicy_audit_log}}',
        '{{%passwordpolicy_blocklist}}',
        '{{%passwordpolicy_notification_log}}',
        '{{%passwordpolicy_notification_templates}}',
        '{{%passwordpolicy_password_history}}',
        '{{%passwordpolicy_policies}}',
        '{{%passwordpolicy_policy_groups}}',
        '{{%passwordpolicy_user_state}}',
    ];

    foreach ($expected as $table) {
        expect(Craft::$app->getDb()->tableExists($table))
            ->toBeTrue("expected {$table} to exist after upgrade migrations ran");
    }
});

it('seeds one password history row per user with a stored password', function() {
    /** @var MigrationTestCase $this */
    // Own the fixture: two users carrying a hash, one carrying none. The
    // assertion is set equality between the seeded userIds and the users
    // matching the migration's own filter, so an extra ambient user can't
    // flip the result either way.
    $withPasswords = [
        $this->seedFixtureUser(fixturePasswordHash('Fixture-Passw0rd!1')),
        $this->seedFixtureUser(fixturePasswordHash('Fixture-Passw0rd!2')),
    ];
    $withoutPassword = $this->seedFixtureUser(null);

    $expectedUserIds = userIdsWithAStoredPassword();

    // Guards against a vacuous pass: the fixture users are on the right
    // sides of the filter before the migration runs.
    expect($expectedUserIds)->toContain(...$withPasswords)
        ->and($expectedUserIds)->not->toContain($withoutPassword);

    runPendingPluginMigrations();

    $seededUserIds = seededHistoryUserIds();

    // One row per matching user: nothing missing, nothing extra, no
    // duplicates (a duplicate would break the canonicalized comparison).
    expect($seededUserIds)->toHaveCount(count($expectedUserIds))
        ->and($seededUserIds)->toEqualCanonicalizing($expectedUserIds);
});

it('stores the current bcrypt hash in each seeded history row', function() {
    /** @var MigrationTestCase $this */
    // Seed a user whose hash this test knows, so the assertion pins "copied
    // verbatim" rather than "matches whatever the users table holds."
    $hash = fixturePasswordHash('Fixture-Passw0rd!3');
    $userId = $this->seedFixtureUser($hash);

    runPendingPluginMigrations();

    $historyRow = (new Query())
        ->select(['userId', 'passwordHash'])
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $userId])
        ->one();

    expect($historyRow)->not->toBeNull()
        ->and($historyRow['passwordHash'])->toBe($hash);
});

it('skips users with null or empty passwords during the history seed', function() {
    /** @var MigrationTestCase $this */
    // The seed filters via `not password = null` AND `not password = ''`.
    // Neither state is reachable through a validated element save, so the
    // fixture helper writes both columns directly — the guard is the
    // contract, and this is the only way to exercise it for real.
    $nullPassword = $this->seedFixtureUser(null);
    $emptyPassword = $this->seedFixtureUser('');
    $storedPassword = $this->seedFixtureUser(fixturePasswordHash('Fixture-Passw0rd!4'));

    runPendingPluginMigrations();

    $seededUserIds = seededHistoryUserIds();

    expect($seededUserIds)->toContain($storedPassword)
        ->and($seededUserIds)->not->toContain($nullPassword)
        ->and($seededUserIds)->not->toContain($emptyPassword);
});

it('is idempotent on re-run: second migrate up does not duplicate rows', function() {
    /** @var MigrationTestCase $this */
    // Own a user so the first pass definitely seeds a row — asserting "the
    // count didn't change" against an empty table would prove nothing.
    $userId = $this->seedFixtureUser(fixturePasswordHash('Fixture-Passw0rd!5'));

    runPendingPluginMigrations();

    $ownedRows = (int)(new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $userId])
        ->count();

    $firstCount = (int)(new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->count();

    expect($ownedRows)->toBe(1)
        ->and($firstCount)->toBeGreaterThanOrEqual(1);

    // Force a re-run: yank the migration history row for the upgrade
    // migration and queue it again. The seed inside `_seedPasswordHistory`
    // exits early when the table already has rows.
    Craft::$app->getDb()->createCommand()
        ->delete(CraftTable::MIGRATIONS, [
            'track' => 'plugin:password-policy',
            'name' => 'm260429_224908_UpgradeTo520Schema',
        ])
        ->execute();

    runPendingPluginMigrations();

    $secondCount = (int)(new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->count();

    expect($secondCount)->toBe($firstCount);
});

it('seeds password history dateCreated in UTC, not the PHP-local wall clock', function() {
    // Regression: the seed previously used a bare `new \DateTime()`, which
    // reads PHP's default timezone. `dateCreated` is a UTC column and
    // retention prune compares against UTC, so a non-UTC server skewed both
    // the stored timestamp and the prune window. The fix pins the seed to
    // `new \DateTime('now', new \DateTimeZone('UTC'))`.
    //
    // Force PHP into a non-UTC zone for the duration of the seed so a
    // regression to the bare constructor produces a timestamp offset by the
    // zone's UTC offset (≈4-5h for New York) — well outside the tolerance
    // window below.
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('America/New_York');

    try {
        $utcBefore = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();

        runPendingPluginMigrations();

        $seeded = (new Query())
            ->select(['dateCreated'])
            ->from('{{%passwordpolicy_password_history}}')
            ->scalar();

        $utcAfter = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($seeded)->not->toBeFalse();

    // The stored string is a UTC wall-clock value. Parse it back as UTC and
    // confirm it sits inside the [before, after] UTC window the seed ran in
    // (allowing a 5s slack for clock granularity). A local-time regression
    // would land hours outside this band.
    $seededTs = (new \DateTime($seeded, new \DateTimeZone('UTC')))->getTimestamp();

    expect($seededTs)->toBeGreaterThanOrEqual($utcBefore - 5)
        ->and($seededTs)->toBeLessThanOrEqual($utcAfter + 5);
});

// =============================================================================
// TX.2 — zero behavior change on 5.1.1 upgrade
// =============================================================================

it('renames pwned to hibp during the project config migration', function() {
    plantLegacyProjectConfig(['pwned' => true]);

    expect(readPluginProjectConfig())->toHaveKey('pwned')
        ->and(readPluginProjectConfig()['pwned'])->toBeTrue();

    runPendingPluginMigrations();

    $settings = readPluginProjectConfig();

    expect($settings)->not->toHaveKey('pwned')
        ->and($settings)->toHaveKey('hibp')
        ->and($settings['hibp'])->toBeTrue();
});

it('renames pwnedFailMode to hibpFailMode during the project config migration', function() {
    plantLegacyProjectConfig(['pwnedFailMode' => 'closed']);

    runPendingPluginMigrations();

    $settings = readPluginProjectConfig();

    expect($settings)->not->toHaveKey('pwnedFailMode')
        ->and($settings)->toHaveKey('hibpFailMode')
        ->and($settings['hibpFailMode'])->toBe('closed');
});

it('preserves the legacy values across the rename rather than resetting to defaults', function() {
    // The rename copies the legacy value verbatim. A site that explicitly
    // disabled HIBP under the old key should still have it disabled after
    // the migration.
    plantLegacyProjectConfig([
        'pwned' => false,
        'pwnedFailMode' => 'open',
    ]);

    runPendingPluginMigrations();

    $settings = readPluginProjectConfig();

    expect($settings['hibp'])->toBeFalse()
        ->and($settings['hibpFailMode'])->toBe('open');
});

it('drops the legacy groupPolicies project config key during upgrade', function() {
    // groupPolicies was an in-cycle 5.2.0-alpha precursor to named
    // policies. It never shipped to a stable release, so real 5.1.1
    // upgraders never had it — this is purely a defensive scrub. Pin
    // the contract anyway because the code path runs and we want a
    // regression alarm if someone strips the cleanup.
    plantLegacyProjectConfig([
        'groupPolicies' => [
            ['groupHandle' => 'editors', 'minLength' => 12],
        ],
    ]);

    runPendingPluginMigrations();

    $settings = readPluginProjectConfig();

    expect($settings)->not->toHaveKey('groupPolicies');
});

it('leaves canonical 5.2.0 keys untouched when no legacy keys are present', function() {
    // Sites freshly upgrading from 5.1.1 with no `pwned` / `pwnedFailMode`
    // in their config (e.g. they accepted defaults) shouldn't see ANY
    // project config write — `_renameProjectConfigKeys()` early-returns
    // when nothing changed.
    $before = readPluginProjectConfig();

    runPendingPluginMigrations();

    $after = readPluginProjectConfig();

    // Canonical keys come from defaults baked into the plugin install.
    // The test shape we care about: the rename cleanup didn't introduce
    // a new key or drop an existing one when no legacy keys were present.
    expect($after)->toBe($before);
});

// =============================================================================
// Notification template seed — included in the upgrade chain via Install
// =============================================================================

it('seeds notification template defaults for every key on the primary site', function() {
    runPendingPluginMigrations();

    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

    $expectedKeys = ['expiry-reminder', 'breach-detected'];

    foreach ($expectedKeys as $key) {
        $exists = (new Query())
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['notificationKey' => $key, 'siteId' => $primarySiteId])
            ->exists();

        expect($exists)->toBeTrue("expected default seed for {$key} on primary site");
    }
});

it('seeds notification template dateCreated in UTC, not the PHP-local wall clock', function() {
    // Same regression class as the password-history seed: the notification
    // template defaults seed (Install + the follow-up default migrations)
    // formerly used a bare `new \DateTime()`. `dateCreated` is a UTC column;
    // the seed now pins UTC explicitly.
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('America/New_York');

    try {
        $utcBefore = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();

        runPendingPluginMigrations();

        $seeded = (new Query())
            ->select(['dateCreated'])
            ->from('{{%passwordpolicy_notification_templates}}')
            ->scalar();

        $utcAfter = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($seeded)->not->toBeFalse();

    $seededTs = (new \DateTime($seeded, new \DateTimeZone('UTC')))->getTimestamp();

    expect($seededTs)->toBeGreaterThanOrEqual($utcBefore - 5)
        ->and($seededTs)->toBeLessThanOrEqual($utcAfter + 5);
});

// =============================================================================
// Follow-up migrations — AddPolicyIdToBlocklist + AddBreachDetectedNotificationDefaults
// =============================================================================

it('adds the policyId column to the blocklist table during the follow-up migration', function() {
    runPendingPluginMigrations();

    $columns = Craft::$app->getDb()->getSchema()
        ->getTableSchema('{{%passwordpolicy_blocklist}}', true)
        ->columns;

    expect($columns)->toHaveKey('policyId');

    // Defensive: the column is nullable so global entries (policyId = NULL)
    // and per-policy entries can coexist.
    expect($columns['policyId']->allowNull)->toBeTrue();
});

it('seeds breach-detected default templates via the follow-up migration', function() {
    // The third follow-up migration (`m260501_140131_*`) is a no-op when
    // Install already seeded the row. We guarantee it works either way:
    // the row exists for every enabled site after the chain runs.
    runPendingPluginMigrations();

    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

    $row = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['notificationKey' => 'breach-detected', 'siteId' => $primarySiteId])
        ->one();

    expect($row)->not->toBeNull()
        ->and($row['content'])->toContain('breach');
});

// =============================================================================
// Migration history — track and applyTime are written for every migration
// =============================================================================

it('records every applied migration in the history table under the plugin track', function() {
    runPendingPluginMigrations();

    $history = (new Query())
        ->select(['name'])
        ->from(CraftTable::MIGRATIONS)
        ->where(['track' => 'plugin:password-policy'])
        ->column();

    $expected = [
        'm260429_224908_UpgradeTo520Schema',
        'm260430_101611_AddPolicyIdToBlocklist',
        'm260430_170841_AddNotificationTemplatesTable',
        'm260501_140131_AddBreachDetectedNotificationDefaults',
        'm260502_214932_AddAuditShapeToPasswordHistory',
    ];

    foreach ($expected as $name) {
        expect($history)->toContain($name);
    }
});

// =============================================================================
// D0 — audit shape migration (m260502_214932_AddAuditShapeToPasswordHistory)
// =============================================================================

it('adds the five audit columns to password_history during upgrade', function() {
    runPendingPluginMigrations();

    $columns = Craft::$app->getDb()->getSchema()
        ->getTableSchema('{{%passwordpolicy_password_history}}', true)
        ->columns;

    expect($columns)->toHaveKeys([
        'changedByUserId',
        'changeReason',
        'changeSourceIp',
        'changeUserAgent',
        'policySnapshot',
    ]);

    // changedByUserId is nullable so audit attribution is optional —
    // CLI runs and migration seeds have no acting admin.
    expect($columns['changedByUserId']->allowNull)->toBeTrue();

    // changeReason carries every enum case, enforced by the database rather
    // than only by the enum class. Where that enforcement LIVES is
    // driver-specific — a MySQL `enum` column type, a PostgreSQL `varchar`
    // plus a CHECK constraint — so the helper resolves whichever definition
    // the current engine uses and the assertion stays single.
    expect(changeReasonClosedListDefinition())
        ->toContain('self_service')
        ->toContain('admin_change')
        ->toContain('admin_force_reset')
        ->toContain('first_login_forced')
        ->toContain('expiry_forced')
        ->toContain('breach_forced')
        ->toContain('cli')
        ->toContain('migration_seed');

    // The default fires on writes that don't explicitly set the column —
    // belt-and-braces against any future call site that bypasses the
    // service layer.
    expect($columns['changeReason']->defaultValue)->toBe('self_service');
});

it('creates the user_state table during upgrade', function() {
    runPendingPluginMigrations();

    $schema = Craft::$app->getDb()->getSchema()->getTableSchema('{{%passwordpolicy_user_state}}', true);

    expect($schema)->not->toBeNull();

    $columns = $schema->columns;

    expect($columns)->toHaveKeys([
        'userId',
        'pendingResetReason',
        'pendingResetSetAt',
        'lastBreachDetectedAt',
        'lastBreachCheckAt',
        'dateCreated',
        'dateUpdated',
        'uid',
    ]);

    // userId is the primary key — every user gets at most one state row.
    expect($schema->primaryKey)->toBe(['userId']);

    // pendingResetReason is nullable (null = no pending reset) and has no
    // default — the absence of a value is meaningful, not a missing flag.
    expect($columns['pendingResetReason']->allowNull)->toBeTrue()
        ->and($columns['pendingResetReason']->defaultValue)->toBeNull();
});

it('seeds password history with changeReason = migration_seed during upgrade', function() {
    runPendingPluginMigrations();

    $reasons = (new Query())
        ->select(['changeReason'])
        ->from('{{%passwordpolicy_password_history}}')
        ->column();

    // Every seeded row carries the migration_seed marker so Phase G
    // audit queries can distinguish migration-seeded rows from real
    // user/admin changes after upgrade.
    expect($reasons)->not->toBeEmpty()
        ->and($reasons)->each->toBe(ChangeReason::MigrationSeed->value);
});

it('leaves changedByUserId null on migration-seeded password history rows', function() {
    runPendingPluginMigrations();

    $changedByValues = (new Query())
        ->select(['changedByUserId'])
        ->from('{{%passwordpolicy_password_history}}')
        ->column();

    // Migration is the operator, not a human — every seeded row leaves
    // changedByUserId null. Synthesizing an admin identity here would
    // break Phase G hash-chain audit semantics.
    expect($changedByValues)->each->toBeNull();
});

it('configures the changedByUserId FK as SET NULL on delete', function() {
    runPendingPluginMigrations();

    expect(foreignKeyDeleteRule('{{%passwordpolicy_password_history}}', 'changedByUserId'))
        ->toBe('SET NULL');
});

it('configures the user_state.userId FK as CASCADE on delete', function() {
    runPendingPluginMigrations();

    expect(foreignKeyDeleteRule('{{%passwordpolicy_user_state}}', 'userId'))
        ->toBe('CASCADE');
});
