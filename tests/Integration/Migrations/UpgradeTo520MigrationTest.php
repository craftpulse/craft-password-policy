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
 * Bootstrap creates exactly one user with a real password (the seed admin
 * from `tests/bootstrap.php`), so the password-history seed produces
 * exactly one row in this fixture. Factory-created users land with
 * password = NULL, which the seed's `not null AND not empty` filter
 * intentionally excludes — pinned in a dedicated test below.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
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

it('seeds the password history table with one row per existing user', function() {
    // Bootstrap leaves exactly one user with a saved password (the seed
    // admin). Snapshot the count of users matching the migration's
    // filter, run the migrations, and assert the seed produced one
    // history row per matching user.
    $userCount = (new Query())
        ->from(CraftTable::USERS)
        ->where(['not', ['password' => null]])
        ->andWhere(['not', ['password' => '']])
        ->count();

    expect($userCount)->toBe('1');

    runPendingPluginMigrations();

    $historyCount = (new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->count();

    expect($historyCount)->toBe('1');
});

it('stores the current bcrypt hash in each seeded history row', function() {
    runPendingPluginMigrations();

    // Bootstrap user — pull both rows and confirm the seed copied
    // password into passwordHash without re-hashing or losing it.
    $userRow = (new Query())
        ->select(['id', 'password'])
        ->from(CraftTable::USERS)
        ->one();

    $historyRow = (new Query())
        ->select(['userId', 'passwordHash'])
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $userRow['id']])
        ->one();

    expect($historyRow)->not->toBeNull()
        ->and($historyRow['passwordHash'])->toBe($userRow['password']);
});

it('skips users with null or empty passwords during the history seed', function() {
    // The migration filters via `not password = null` AND `not password = ''`.
    // We can't easily insert a user with a NULL password through the
    // factory (Craft's User::beforeSave normalises that), but the query
    // guard is the contract — pin it by asserting the seed row count
    // never exceeds the count of users with a real password.
    UserFactory::admin();

    $usersWithPasswords = (new Query())
        ->from(CraftTable::USERS)
        ->where(['not', ['password' => null]])
        ->andWhere(['not', ['password' => '']])
        ->count();

    runPendingPluginMigrations();

    $historyCount = (new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->count();

    expect($historyCount)->toBe($usersWithPasswords);
});

it('is idempotent on re-run — second migrate up does not duplicate rows', function() {
    runPendingPluginMigrations();

    $firstCount = (new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->count();

    expect($firstCount)->toBe('1');

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

    $secondCount = (new Query())
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

    // changeReason carries every enum case; the column type is the
    // canonical place to surface the closed list.
    expect($columns['changeReason']->dbType)
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

    $rule = (new Query())
        ->select(['DELETE_RULE'])
        ->from('information_schema.REFERENTIAL_CONSTRAINTS rc')
        ->innerJoin(
            'information_schema.KEY_COLUMN_USAGE kcu',
            'rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME AND rc.CONSTRAINT_SCHEMA = kcu.CONSTRAINT_SCHEMA',
        )
        ->where([
            'rc.CONSTRAINT_SCHEMA' => Craft::$app->getDb()->createCommand('SELECT DATABASE()')->queryScalar(),
            'kcu.TABLE_NAME' => Craft::$app->getDb()->getSchema()->getRawTableName('{{%passwordpolicy_password_history}}'),
            'kcu.COLUMN_NAME' => 'changedByUserId',
        ])
        ->scalar();

    expect($rule)->toBe('SET NULL');
});

it('configures the user_state.userId FK as CASCADE on delete', function() {
    runPendingPluginMigrations();

    $rule = (new Query())
        ->select(['DELETE_RULE'])
        ->from('information_schema.REFERENTIAL_CONSTRAINTS rc')
        ->innerJoin(
            'information_schema.KEY_COLUMN_USAGE kcu',
            'rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME AND rc.CONSTRAINT_SCHEMA = kcu.CONSTRAINT_SCHEMA',
        )
        ->where([
            'rc.CONSTRAINT_SCHEMA' => Craft::$app->getDb()->createCommand('SELECT DATABASE()')->queryScalar(),
            'kcu.TABLE_NAME' => Craft::$app->getDb()->getSchema()->getRawTableName('{{%passwordpolicy_user_state}}'),
            'kcu.COLUMN_NAME' => 'userId',
        ])
        ->scalar();

    expect($rule)->toBe('CASCADE');
});
