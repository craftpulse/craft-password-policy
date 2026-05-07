<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use Craft;
use craft\db\Connection;
use craft\db\Migration;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\data\EmailDefaults;
use craftpulse\passwordpolicy\enums\ChangeReason;

/**
 * Class Install
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class Install extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeUp(): bool
    {
        $this->_createPasswordHistoryTable();
        $this->_createAuditLogTable();
        $this->_createNotificationLogTable();
        $this->_createPoliciesTable();
        $this->_createPolicyGroupsTable();
        $this->_createBlocklistTable();
        $this->_createNotificationTemplatesTable();
        $this->_createUserStateTable();
        $this->_createAlertCooldownsTable();
        $this->_createSiemForwardersTable();
        $this->_createWebhookEndpointsTable();
        $this->_seedNotificationTemplateDefaults();

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%passwordpolicy_webhook_endpoints}}');
        $this->dropTableIfExists('{{%passwordpolicy_siem_forwarders}}');
        $this->dropTableIfExists('{{%passwordpolicy_alert_cooldowns}}');
        $this->dropTableIfExists('{{%passwordpolicy_user_state}}');
        $this->dropTableIfExists('{{%passwordpolicy_notification_templates}}');
        $this->dropTableIfExists('{{%passwordpolicy_blocklist}}');
        $this->dropTableIfExists('{{%passwordpolicy_policy_groups}}');
        $this->dropTableIfExists('{{%passwordpolicy_policies}}');
        $this->dropTableIfExists('{{%passwordpolicy_notification_log}}');
        $this->dropTableIfExists('{{%passwordpolicy_audit_log}}');
        $this->dropTableIfExists('{{%passwordpolicy_password_history}}');

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Creates the password history table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createPasswordHistoryTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_password_history}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_password_history}}', [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'changedByUserId' => $this->integer()->null(),
            'passwordHash' => $this->string()->notNull(),
            'changeReason' => $this->_changeReasonColumnType(
                columnName: 'changeReason',
                notNull: true,
                defaultValue: ChangeReason::SelfService->value,
            ),
            'changeSourceIp' => $this->string(45)->null(),
            'changeUserAgent' => $this->text()->null(),
            'policySnapshot' => $this->string(64)->null(),
            'dateCreated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_password_history}}', ['userId', 'dateCreated'], false);
        $this->createIndex(null, '{{%passwordpolicy_password_history}}', ['changedByUserId'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_password_history}}', ['userId'], Table::USERS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, '{{%passwordpolicy_password_history}}', ['changedByUserId'], Table::USERS, ['id'], 'SET NULL', null);
    }

    /**
     * Creates the audit log table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createAuditLogTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_audit_log}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_audit_log}}', [
            'id' => $this->primaryKey(),
            'userId' => $this->integer(),
            'changedByUserId' => $this->integer(),
            'event' => $this->string()->notNull(),
            'outcome' => $this->string()->notNull()->defaultValue('success'),
            'source' => $this->string(),
            'details' => $this->json(),
            'ipHash' => $this->string(),
            'userIdentifier' => $this->string(),
            // Hash-chain columns. No DB-level default on fresh installs —
            // the chain-aware `AuditLogService::logEvent()` populates both
            // on insert from the genesis row onwards. The default `'0'`
            // exists only on the upgrade migration
            // (m260507_081201_AddRowHashAndPreviousHashToAuditLog) where
            // legacy rows need a placeholder before the recompute pass.
            'rowHash' => $this->char(64)->notNull(),
            'previousHash' => $this->char(64)->notNull(),
            // Consumed by the G8 SIEM forwarder. NULL = unforwarded.
            'forwardedAt' => $this->dateTime()->null(),
            'forwardAttempts' => $this->integer()->notNull()->defaultValue(0),
            'dateCreated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_audit_log}}', ['userId'], false);
        $this->createIndex(null, '{{%passwordpolicy_audit_log}}', ['event', 'dateCreated'], false);
        $this->createIndex(null, '{{%passwordpolicy_audit_log}}', ['forwardedAt'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_audit_log}}', ['userId'], Table::USERS, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, '{{%passwordpolicy_audit_log}}', ['changedByUserId'], Table::USERS, ['id'], 'SET NULL', null);
    }

    /**
     * Creates the blocklist table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createBlocklistTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_blocklist}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_blocklist}}', [
            'id' => $this->primaryKey(),
            'word' => $this->string()->notNull(),
            'source' => $this->string()->notNull()->defaultValue('common'),
            'policyId' => $this->integer()->null(),
            'dateCreated' => $this->dateTime()->notNull(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_blocklist}}', ['word'], true);
        $this->createIndex(null, '{{%passwordpolicy_blocklist}}', ['policyId'], false);
        $this->addForeignKey(
            null,
            '{{%passwordpolicy_blocklist}}',
            ['policyId'],
            '{{%passwordpolicy_policies}}',
            ['id'],
            'CASCADE',
            null,
        );
    }

    /**
     * Creates the notification log table for dedup tracking.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createNotificationLogTable(): void
    {
        $table = '{{%passwordpolicy_notification_log}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'notificationType' => $this->string()->notNull(),
            'status' => $this->string(16)->notNull()->defaultValue('sent'),
            'recipientEmail' => $this->string()->null(),
            'siteId' => $this->integer()->null(),
            'subject' => $this->text()->null(),
            'body' => $this->mediumText()->null(),
            'errorMessage' => $this->text()->null(),
            'resentFromId' => $this->integer()->null(),
            'sentAt' => $this->dateTime()->notNull(),
        ]);

        $this->createIndex(null, $table, ['userId', 'notificationType', 'sentAt'], false);
        $this->createIndex(null, $table, ['status', 'sentAt'], false);
        $this->createIndex(null, $table, ['siteId'], false);
        $this->createIndex(null, $table, ['resentFromId'], false);
        $this->addForeignKey(null, $table, ['userId'], Table::USERS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $table, ['siteId'], Table::SITES, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $table, ['resentFromId'], $table, ['id'], 'SET NULL', null);
    }

    /**
     * Creates the policies table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createPoliciesTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_policies}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_policies}}', [
            'id' => $this->primaryKey(),
            'name' => $this->string(255)->notNull(),
            'handle' => $this->string(255)->notNull(),
            'preset' => $this->string(64)->null(),
            'settings' => $this->json()->notNull(),
            'sortOrder' => $this->smallInteger()->notNull()->defaultValue(0),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_policies}}', ['handle'], true);
    }

    /**
     * Creates the policy groups junction table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createPolicyGroupsTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_policy_groups}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_policy_groups}}', [
            'id' => $this->primaryKey(),
            'policyId' => $this->integer()->notNull(),
            'groupId' => $this->integer()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_policy_groups}}', ['policyId', 'groupId'], true);
        $this->createIndex(null, '{{%passwordpolicy_policy_groups}}', ['groupId'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_policy_groups}}', ['policyId'], '{{%passwordpolicy_policies}}', ['id'], 'CASCADE', null);
        $this->addForeignKey(null, '{{%passwordpolicy_policy_groups}}', ['groupId'], Table::USERGROUPS, ['id'], 'CASCADE', null);
    }

    /**
     * Creates the notification templates table.
     *
     * One row per (notificationKey, siteId) combination, with a JSON
     * `content` column holding subject/body/sender overrides — mirrors
     * Craft 5's element content storage shape.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createNotificationTemplatesTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_notification_templates}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_notification_templates}}', [
            'id' => $this->primaryKey(),
            'notificationKey' => $this->string(64)->notNull(),
            'siteId' => $this->integer()->notNull(),
            'content' => $this->json()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(
            null,
            '{{%passwordpolicy_notification_templates}}',
            ['notificationKey', 'siteId'],
            true,
        );
        $this->createIndex(
            null,
            '{{%passwordpolicy_notification_templates}}',
            ['siteId'],
            false,
        );
        $this->addForeignKey(
            null,
            '{{%passwordpolicy_notification_templates}}',
            ['siteId'],
            Table::SITES,
            ['id'],
            'CASCADE',
            null,
        );
    }

    /**
     * Creates the per-user state table tracking pending-reset reasons +
     * breach-detection state. One sparsely-populated row per user; FK
     * CASCADE on userId so the row is removed when the user is deleted.
     *
     * The `pendingResetReason` column uses the same cross-DB-safe column
     * type as `passwordpolicy_password_history.changeReason` (MySQL
     * `ENUM`, PostgreSQL `VARCHAR + CHECK`, SQLite plain `VARCHAR`) — but
     * nullable with no default, so `NULL` means "no pending reset."
     *
     * Capture across editions, gate exposure (memory rule
     * `project_audit_capture_principle.md`).
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createUserStateTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_user_state}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_user_state}}', [
            'userId' => $this->integer()->notNull(),
            'pendingResetReason' => $this->_changeReasonColumnType(
                columnName: 'pendingResetReason',
                notNull: false,
                defaultValue: null,
            ),
            'pendingResetSetAt' => $this->dateTime()->null(),
            'lastBreachDetectedAt' => $this->dateTime()->null(),
            'lastBreachCheckAt' => $this->dateTime()->null(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
            'PRIMARY KEY([[userId]])',
        ]);

        $this->addForeignKey(
            null,
            '{{%passwordpolicy_user_state}}',
            ['userId'],
            Table::USERS,
            ['id'],
            'CASCADE',
            null,
        );
    }

    /**
     * Creates the alert cooldowns table — durable storage for the per-
     * (eventClass, cooldownKey) suppression record that
     * {@see \craftpulse\passwordpolicy\services\AlertCooldownService}
     * maintains. Pairs with `passwordpolicy_notification_log`: the log
     * answers "what was sent + when + with what subject/body", the
     * cooldowns table answers "when alerting fired regardless of
     * whether an email or row was emitted".
     *
     * No FK constraints — events outlive entities by design. A deleted
     * user's cooldown rows still answer "did we suppress an alert at
     * the time?" for auditors after the user is gone.
     *
     * Capture is universal across editions per memory rule
     * `project_audit_capture_principle.md`.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createAlertCooldownsTable(): void
    {
        $table = '{{%passwordpolicy_alert_cooldowns}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'eventClass' => $this->string(128)->notNull(),
            'cooldownKey' => $this->string(191)->notNull(),
            'firedAt' => $this->dateTime()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['eventClass'], false);
        $this->createIndex(null, $table, ['cooldownKey'], false);
        $this->createIndex(null, $table, ['firedAt'], false);
        // Composite index = the dedup hot path. Ordered (eventClass,
        // cooldownKey, firedAt) so a `WHERE eventClass = ? AND
        // cooldownKey = ? AND firedAt >= ?` query lands on a covering
        // prefix scan and the index can serve the >= range from the
        // last column.
        $this->createIndex(null, $table, ['eventClass', 'cooldownKey', 'firedAt'], false);
    }

    /**
     * Creates the SIEM forwarders table — the registry of syslog-over-TLS
     * endpoints the plugin forwards audit-log rows to (G8). Mirror of
     * {@see m260507_132250_AddSiemForwardersTable}; that migration runs on
     * upgrade-from-2.6 sites, this private method runs on fresh installs.
     *
     * Capture is universal across editions; the forwarder *registry* is
     * exposure (Enterprise-only CP surface). The table exists empty on
     * Lite / Pro and that's the correct state per
     * `project_audit_capture_principle.md`.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createSiemForwardersTable(): void
    {
        $table = '{{%passwordpolicy_siem_forwarders}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'name' => $this->string()->null(),
            'protocol' => $this->string(32)->notNull()->defaultValue('syslog-tls'),
            'host' => $this->string()->notNull(),
            'port' => $this->integer()->notNull(),
            'tlsCertVerify' => $this->boolean()->notNull()->defaultValue(true),
            'tlsCaBundlePath' => $this->string()->null(),
            'eventClasses' => $this->json()->null(),
            'enabled' => $this->boolean()->notNull()->defaultValue(true),
            'circuitOpenAt' => $this->dateTime()->null(),
            'consecutiveFailures' => $this->integer()->notNull()->defaultValue(0),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['enabled'], false);
        $this->createIndex(null, $table, ['circuitOpenAt'], false);
    }

    /**
     * Creates the webhook endpoints table — the registry of HTTP webhook
     * subscribers the plugin POSTs HMAC-signed audit payloads to (G9).
     * Mirror of {@see m260507_175059_AddWebhookEndpointsTable}; that
     * migration runs on upgrade-from-2.7 sites, this private method runs
     * on fresh installs.
     *
     * Capture is universal across editions; the endpoint *registry* is
     * exposure (Enterprise-only CP surface). The table exists empty on
     * Lite / Pro and that's the correct state per
     * `project_audit_capture_principle.md`.
     *
     * Differs from the SIEM forwarders table (G8): each endpoint carries
     * a `lastDeliveredRowId` watermark for per-endpoint dispatch
     * tracking. Webhooks are independent subscribers — endpoint A's
     * success doesn't mark endpoint B's row delivered.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createWebhookEndpointsTable(): void
    {
        $table = '{{%passwordpolicy_webhook_endpoints}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'name' => $this->string()->null(),
            'url' => $this->string(2048)->notNull(),
            'secretCurrent' => $this->text()->notNull(),
            'secretPrevious' => $this->text()->null(),
            'secretRotatedAt' => $this->dateTime()->null(),
            'eventClasses' => $this->json()->null(),
            'enabled' => $this->boolean()->notNull()->defaultValue(true),
            'lastDeliveredRowId' => $this->bigInteger()->null(),
            'consecutiveFailures' => $this->integer()->notNull()->defaultValue(0),
            'circuitOpenAt' => $this->dateTime()->null(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['enabled'], false);
        $this->createIndex(null, $table, ['circuitOpenAt'], false);
        $this->createIndex(null, $table, ['lastDeliveredRowId'], false);
    }

    /**
     * Returns the cross-DB column-type clause for `changeReason`-shaped
     * columns. Single source of truth = the PHP `ChangeReason` enum.
     * Mirrors {@see m260502_214932_AddAuditShapeToPasswordHistory}'s
     * private helper of the same name — kept in both places so fresh
     * installs and upgrade-from-5.1.1 sites land on identical column
     * types without depending on each other.
     *
     * Adding a new enum case requires a follow-up migration that runs
     * `ALTER TABLE ... MODIFY changeReason ENUM(...)` (MySQL) or drops
     * and recreates the CHECK constraint (PostgreSQL) with the extended
     * value list — and a sync update to this private helper if Install
     * is ever the only path that builds the schema.
     *
     * @param string $columnName used in the PostgreSQL CHECK clause; the
     *     same function is reused for `changeReason` and
     *     `pendingResetReason` columns
     * @param bool $notNull when true, the clause adds `NOT NULL`
     * @param string|null $defaultValue when set, adds `DEFAULT '...'`
     * @return string raw column-type clause
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _changeReasonColumnType(string $columnName, bool $notNull, ?string $defaultValue): string
    {
        $values = ChangeReason::values();
        $valuesQuoted = "'" . implode("','", $values) . "'";

        $nullClause = $notNull ? ' NOT NULL' : ' NULL';
        $defaultClause = $defaultValue !== null
            ? " DEFAULT '{$defaultValue}'"
            : '';

        if ($this->db->getDriverName() === Connection::DRIVER_MYSQL) {
            return "ENUM({$valuesQuoted}){$nullClause}{$defaultClause}";
        }

        if ($this->db->getDriverName() === Connection::DRIVER_PGSQL) {
            return "VARCHAR(32){$nullClause}{$defaultClause} CHECK (\"{$columnName}\" IN ({$valuesQuoted}))";
        }

        // SQLite / fallback — no constraint, application layer enforces.
        return "VARCHAR(32){$nullClause}{$defaultClause}";
    }

    /**
     * Seeds default rows for every (notificationKey × enabled site)
     * combination so the runtime never falls back to translation files.
     *
     * Idempotent — skips rows that already exist.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _seedNotificationTemplateDefaults(): void
    {
        $sites = Craft::$app->getSites()->getAllSites();
        $now = (new \DateTime())->format('Y-m-d H:i:s');

        foreach (EmailDefaults::all() as $key => $factory) {
            $content = call_user_func($factory);
            $contentJson = Json::encode($content);

            foreach ($sites as $site) {
                $exists = (new Query())
                    ->from('{{%passwordpolicy_notification_templates}}')
                    ->where([
                        'notificationKey' => $key,
                        'siteId' => $site->id,
                    ])
                    ->exists();

                if ($exists) {
                    continue;
                }

                $this->insert('{{%passwordpolicy_notification_templates}}', [
                    'notificationKey' => $key,
                    'siteId' => $site->id,
                    'content' => $contentJson,
                    'dateCreated' => $now,
                    'dateUpdated' => $now,
                    'uid' => StringHelper::UUID(),
                ]);
            }
        }
    }
}
