<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Non-transactional Pest TestCase for migration replay tests.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use Craft;
use craft\db\Connection;
use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\migrations\Install as PluginInstall;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\TestCase;
use RuntimeException;
use yii\db\Exception as DbException;

/**
 * Base TestCase for migration-replay tests (T1.2 + TX.2).
 *
 * Migration tests can't run inside the standard transaction wrapper because
 * MySQL/MariaDB auto-commit DDL — `DROP TABLE` / `CREATE TABLE` aren't
 * rolled back when the transaction rolls back. The base
 * {@see TestCase::usesTransaction()} returns true; this subclass overrides
 * to false and takes responsibility for restoring `db_test` to the canonical
 * 5.2.0 schema in `tearDown` so the next test class sees a clean baseline.
 *
 * `tearDownPluginSchema()` (callable from beforeEach) drops every plugin
 * table and removes every plugin migration history row — yielding a
 * 5.1.1-shaped state where Craft is installed but the plugin isn't yet
 * upgraded. Tests fabricate any 5.1.1-era project-config keys they need
 * (e.g. `pwned: true`) on top of that, then replay migrations.
 *
 * `restorePluginSchema()` (always run in tearDown) rebuilds the 5.2.0
 * schema by running every plugin migration through the migrator —
 * idempotent because every `_create*Table()` private method in
 * `Install.php` is guarded by `tableExists`, and every project-config
 * rename in `m260429_224908_UpgradeTo520Schema` is guarded by
 * `array_key_exists`.
 *
 * The bcrypt seed loop in the upgrade migration toggles
 * `enableLogging`/`enableProfiling` off internally — tests don't need to
 * worry about that. Tests that seed their own bcrypt hashes (e.g. T1.2
 * fixture preconditions) MUST replicate the same suppression pattern
 * (see security.md).
 *
 * Stale rows in the `migrations` table from re-applied migrations across
 * tests are cosmetic — Craft's migrator queries by name + track, so a
 * duplicate row won't break re-runs. We intentionally don't try to dedupe
 * them.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
abstract class MigrationTestCase extends TestCase
{
    // Private Properties
    // =========================================================================

    /**
     * Element IDs of every user row seeded through {@see seedFixtureUser()}
     * during the current test. Deleted in `tearDown` so a non-transactional
     * migration test never leaves users behind in `db_test`.
     *
     * @var int[]
     */
    private array $_fixtureUserIds = [];

    // Public Methods
    // =========================================================================

    /**
     * Seeds a user row carrying the given raw `users.password` value and
     * returns its element ID.
     *
     * Tests that assert on the upgrade migration's password-history seed need
     * to OWN the users they count, rather than leaning on whatever the
     * bootstrap or a sibling test happens to have left in `db_test`.
     *
     * The row is cloned from an existing user (`elements` + `users` +
     * `elements_sites`) with a fresh ID, UID, username, and email, then the
     * password column is overwritten. Two reasons for raw SQL over
     * {@see \craftpulse\passwordpolicy\tests\Support\Factories\UserFactory}:
     *
     * 1. Callers seed AFTER {@see tearDownPluginSchema()}, and a real element
     *    save at that point runs the plugin's `User::EVENT_DEFINE_RULES`
     *    validators and its `EVENT_AFTER_SAVE` history writer against plugin
     *    tables that no longer exist.
     * 2. `password = NULL` and `password = ''` are exactly the states the
     *    migration's seed filter excludes, and neither is reachable through a
     *    validated element save.
     *
     * Cloning rather than hand-listing columns keeps the helper working
     * across Craft schema changes.
     *
     * @param string|null $password Raw value for the `users.password` column.
     * Pass a bcrypt hash for a "has a password" user, or `null` / `''` for the
     * states the seed filter skips.
     * @return int
     *
     * @throws DbException
     * @throws RuntimeException if there's no existing user row to clone.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function seedFixtureUser(?string $password): int
    {
        $db = Craft::$app->getDb();

        $templateElement = (new Query())
            ->from(CraftTable::ELEMENTS)
            ->where(['type' => User::class, 'dateDeleted' => null])
            ->orderBy(['id' => SORT_ASC])
            ->one();

        if (!is_array($templateElement)) {
            throw new RuntimeException(
                'Cannot seed a fixture user: no existing user element row to clone from.',
            );
        }

        $templateId = (int)$templateElement['id'];
        unset($templateElement['id']);
        $templateElement['uid'] = StringHelper::UUID();

        $db->createCommand()->insert(CraftTable::ELEMENTS, $templateElement)->execute();
        $userId = (int)$db->getLastInsertID();

        $templateUser = (new Query())
            ->from(CraftTable::USERS)
            ->where(['id' => $templateId])
            ->one();

        if (!is_array($templateUser)) {
            throw new RuntimeException(
                sprintf('Cannot seed a fixture user: user row %d is missing.', $templateId),
            );
        }

        $unique = bin2hex(random_bytes(4));

        // The cloned row is the source of truth for the column list (`users`
        // carries no `uid` — that lives on `elements`), so only override
        // columns the current schema actually has.
        $templateUser = $this->_override($templateUser, [
            'id' => $userId,
            'username' => "fixture-{$unique}",
            'email' => "fixture-{$unique}@craftpulse.test",
            'password' => $password,
            'verificationCode' => null,
            'verificationCodeIssuedDate' => null,
        ]);

        $db->createCommand()->insert(CraftTable::USERS, $templateUser)->execute();

        $templateSite = (new Query())
            ->from(CraftTable::ELEMENTS_SITES)
            ->where(['elementId' => $templateId])
            ->one();

        if (is_array($templateSite)) {
            unset($templateSite['id']);

            $templateSite = $this->_override($templateSite, [
                'elementId' => $userId,
                'uid' => StringHelper::UUID(),
            ]);

            $db->createCommand()->insert(CraftTable::ELEMENTS_SITES, $templateSite)->execute();
        }

        $this->_fixtureUserIds[] = $userId;

        return $userId;
    }

    /**
     * Drops every plugin table and removes every plugin migration history
     * row, yielding a "5.1.1-shaped" state where Craft is installed but
     * the plugin's schema doesn't exist.
     *
     * Public so test files can call it from a Pest closure (`beforeEach`
     * has no `$this` scope inheritance — it's a real anonymous function
     * bound to the TestCase, not an inline method on it). Pest tests
     * that use this base call `$this->tearDownPluginSchema()` directly.
     *
     * Drop order respects FK dependencies: `notification_templates` and
     * `blocklist` reference `policies` and `sites`/`users`; `policy_groups`
     * references `policies` and `usergroups`; `password_history`,
     * `audit_log`, and `notification_log` reference `users`. Reverse-FK
     * order matches `Install::safeDown()`.
     *
     * Idempotent — `dropTableIfExists` swallows missing tables.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function tearDownPluginSchema(): void
    {
        $db = Craft::$app->getDb();

        // Disable FK checks for the duration of the drop — paranoid but
        // safe. MySQL would normally let us drop in reverse-FK order, but
        // some test orders may leave orphan rows referencing deleted
        // policies, etc. The next migration replay rebuilds clean state.
        //
        // MySQL only: `SET FOREIGN_KEY_CHECKS` is a MySQL session variable and
        // PostgreSQL has no equivalent. It doesn't need one here, because the
        // drop list below is already in reverse-FK order and PostgreSQL
        // enforces constraints per statement rather than deferring them.
        $isMysql = $db->getDriverName() === Connection::DRIVER_MYSQL;

        if ($isMysql) {
            $db->createCommand('SET FOREIGN_KEY_CHECKS = 0')->execute();
        }

        try {
            foreach ([
                '{{%passwordpolicy_siem_forwarders}}',
                '{{%passwordpolicy_alert_cooldowns}}',
                '{{%passwordpolicy_user_state}}',
                '{{%passwordpolicy_notification_templates}}',
                '{{%passwordpolicy_blocklist}}',
                '{{%passwordpolicy_policy_groups}}',
                '{{%passwordpolicy_policies}}',
                '{{%passwordpolicy_notification_log}}',
                '{{%passwordpolicy_audit_log}}',
                '{{%passwordpolicy_password_history}}',
            ] as $table) {
                $db->createCommand()->dropTableIfExists($table)->execute();
            }
        } finally {
            if ($isMysql) {
                $db->createCommand('SET FOREIGN_KEY_CHECKS = 1')->execute();
            }
        }

        // Wipe migration history so `getNewMigrations()` re-discovers them.
        // Track is `plugin:<handle>` per `Plugins::_setPluginMigrator()`.
        $db->createCommand()
            ->delete(CraftTable::MIGRATIONS, ['track' => 'plugin:password-policy'])
            ->execute();

        // Refresh the schema cache — Craft caches table metadata between
        // queries and the upcoming migrate-up reads `tableExists` against
        // the cached state.
        $db->getSchema()->refresh();
    }

    /**
     * Rebuilds the 5.2.0 schema after a teardown. Idempotent.
     *
     * Calling `Install::safeUp()` directly is the cheapest path — every
     * `_create*Table()` is `tableExists`-guarded, so a partial drop or a
     * mid-test crash still recovers cleanly. The migrator's history rows
     * are then re-inserted manually so `getNewMigrations()` doesn't try
     * to re-apply already-applied migrations on the next test boot.
     *
     * Migration history insertion uses the migrator's `addMigrationHistory`
     * to keep the `track` and `applyTime` columns consistent with what
     * Craft writes during a normal `migrate/up` run.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function restorePluginSchema(): void
    {
        $migrator = PasswordPolicy::$plugin->getMigrator();
        $db = Craft::$app->getDb();
        $db->getSchema()->refresh();

        // Build the schema (Install is idempotent on every table).
        (new PluginInstall())->up(true);

        // Re-record every plugin migration as applied so the migrator's
        // `getNewMigrations()` query doesn't queue them on the next test.
        $migrationFiles = [
            'm260429_224908_UpgradeTo520Schema',
            'm260430_101611_AddPolicyIdToBlocklist',
            'm260430_170841_AddNotificationTemplatesTable',
            'm260501_140131_AddBreachDetectedNotificationDefaults',
            'm260502_214932_AddAuditShapeToPasswordHistory',
            'm260506_174529_AddNotificationLogActivityColumns',
            'm260507_081201_AddRowHashAndPreviousHashToAuditLog',
            'm260507_081852_RecomputeAuditLogChain',
            'm260507_122940_AddAlertCooldownsTable',
            'm260507_132250_AddSiemForwardersTable',
        ];

        $existingHistory = $migrator->getMigrationHistory();

        foreach ($migrationFiles as $name) {
            if (!isset($existingHistory[$name])) {
                $migrator->addMigrationHistory($name);
            }
        }

        $db->getSchema()->refresh();
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function tearDown(): void
    {
        // Migration tests run outside the transaction wrap, so every seeded
        // user committed. Delete them before restoring the schema — the
        // `elements` row cascades to `users`, `elements_sites`, and every
        // plugin table keyed on `userId`.
        $this->_deleteFixtureUsers();

        // Always restore — even if the test failed mid-way, the next test
        // class needs a 5.2.0-shaped schema or it'll see "table doesn't
        // exist" cascading failures.
        $this->restorePluginSchema();

        parent::tearDown();
    }

    /**
     * Migration tests run outside the standard transaction wrap because
     * DDL is auto-committed in MySQL/MariaDB and can't be rolled back.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function usesTransaction(): bool
    {
        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Applies `$overrides` to a cloned table row, skipping any column the row
     * doesn't carry. Keeps {@see seedFixtureUser()} working across Craft
     * schema changes: the clone defines the column list, the overrides only
     * narrow it.
     *
     * @param array<string, mixed> $row
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _override(array $row, array $overrides): array
    {
        foreach ($overrides as $column => $value) {
            if (array_key_exists($column, $row)) {
                $row[$column] = $value;
            }
        }

        return $row;
    }

    /**
     * Hard-deletes every user seeded through {@see seedFixtureUser()}.
     *
     * Deleting the `elements` row is enough: `users`, `elements_sites`, and
     * the plugin's `userId` foreign keys all cascade from it. Runs before
     * {@see restorePluginSchema()} so it works whether or not the test left
     * the plugin tables in place.
     *
     * @return void
     *
     * @throws DbException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _deleteFixtureUsers(): void
    {
        if ($this->_fixtureUserIds === []) {
            return;
        }

        Craft::$app->getDb()->createCommand()
            ->delete(CraftTable::ELEMENTS, ['id' => $this->_fixtureUserIds])
            ->execute();

        $this->_fixtureUserIds = [];
    }
}
