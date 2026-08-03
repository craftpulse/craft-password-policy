<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use Craft;
use craft\db\Connection;
use craft\db\Migration;
use craft\db\Query;
use craft\db\Table;
use craft\errors\MigrationException;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\auditkit\AuditKit;
use craftpulse\passwordpolicy\data\EmailDefaults;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\elements\PolicyElement;
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
     * Pumps the shared Audit Kit migrator on its own `module:audit-kit` track
     * before PP's schema lands. Audit Kit is a library-shipped Yii module, so
     * Craft never runs its migrations: the seam that lets a kit migration reach
     * every install is each consumer's `Install`, and it is wired even while the
     * kit ships none, so the next fresh install is correct without a coordinated
     * release across every consumer.
     *
     * There is deliberately no matching `getMigrator()->down()` in
     * {@see safeDown()}. The kit is shared by every installed consumer and one
     * plugin's uninstall must not tear down state the others still rely on.
     *
     * `AuditKit::getInstance()` registers the module lazily, so this works even
     * when the migration runs before PP's own `init()` wiring.
     *
     * @throws MigrationException from `MigrationManager::up()` when a kit
     *     migration fails.
     *
     * @author CraftPulse
     */
    public function safeUp(): bool
    {
        AuditKit::getInstance()->getMigrator()->up();

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
        $this->_createKnownDevicesTable();
        $this->_createGroupAlertSubscriptionsTable();
        $this->_createApiTokensTable();
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
        // Delete `craft_elements` rows for our element types before
        // dropping the per-element record tables. The record tables FK
        // to `craft_elements.id` with ON DELETE CASCADE, but dropping
        // a record table doesn't cascade in the other direction —
        // `craft_elements` rows would be orphaned on uninstall.
        // `craft_elements_sites` has its own FK on
        // `craft_elements.id` with ON DELETE CASCADE so it cleans up
        // automatically.
        $this->db->createCommand()
            ->delete(Table::ELEMENTS, [
                'type' => [
                    AuditLogElement::class,
                    NotificationLogElement::class,
                    PolicyElement::class,
                ],
            ])
            ->execute();

        $this->dropTableIfExists('{{%passwordpolicy_api_tokens}}');
        $this->dropTableIfExists('{{%passwordpolicy_group_alert_subscriptions}}');
        $this->dropTableIfExists('{{%passwordpolicy_known_devices}}');
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
     * Element-backed (Craft 5 idiom). `id` is a FK to `craft_elements.id`
     * with `ON DELETE CASCADE`. The chain bytes (`rowHash`, `previousHash`,
     * canonical payload) are unchanged from the pre-element shape — the
     * `id` column is NOT in the canonical payload that
     * `AuditLogService::canonicalize()` hashes, so the chain hashes
     * verify byte-identically across the element-ification refactor.
     *
     * `userId` is nullable + `SET NULL` so audit history outlives the
     * user — aligns with `project_audit_capture_principle.md` (events
     * outlive entities by design). `changedByUserId` follows the same
     * pattern.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createAuditLogTable(): void
    {
        $table = '{{%passwordpolicy_audit_log}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->integer()->notNull(),
            'userId' => $this->integer()->null(),
            'changedByUserId' => $this->integer()->null(),
            'event' => $this->string()->notNull(),
            'outcome' => $this->string()->notNull()->defaultValue('success'),
            'source' => $this->string(),
            'details' => $this->json(),
            'ipHash' => $this->string(),
            // Immutable HMAC identities — these, NOT the mutable `userId` /
            // `changedByUserId` FK ints, are what the canonical hash-chain
            // payload hashes. Both FK columns are `ON DELETE SET NULL`, so
            // deleting a user nulls them on every historical row; hashing
            // them would make a GDPR erasure indistinguishable from log
            // tampering (the verifier would recompute a different rowHash).
            // The HMAC identifiers are set once at write and never mutate.
            'userIdentifier' => $this->string(),
            'changedByIdentifier' => $this->string(),
            // Geolocation enrichment (Feature 4). Country code + region
            // resolved from the request IP via the bundled DB-IP Lite
            // database; the raw IP is NEVER stored. Both EXCLUDED from the
            // canonical hash-chain payload — geo is post-insert metadata,
            // same exclusion class as `forwardedAt`/`forwardAttempts`.
            // Columns exist on every edition (capture is universal);
            // population is gated on Enterprise + `geoIpEnabled` at the
            // service call site.
            'geoCountry' => $this->char(2)->null(),
            'geoRegion' => $this->string()->null(),
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
            'PRIMARY KEY([[id]])',
        ]);

        $this->createIndex(null, $table, ['userId'], false);
        $this->createIndex(null, $table, ['event', 'dateCreated'], false);
        $this->createIndex(null, $table, ['forwardedAt'], false);
        $this->addForeignKey(null, $table, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $table, ['userId'], Table::USERS, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $table, ['changedByUserId'], Table::USERS, ['id'], 'SET NULL', null);
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
     * Creates the notification log table.
     *
     * Element-backed (Craft 5 idiom): `id` is a FK to `craft_elements.id`
     * with `ON DELETE CASCADE`. Pairs with
     * {@see \craftpulse\passwordpolicy\elements\NotificationLogElement}
     * and {@see \craftpulse\passwordpolicy\records\NotificationLogRecord}
     * — the element provides the queryable + index surface, the record
     * stays the storage layer. Mirror of
     * {@see m260511_133103_ConvertNotificationLogToElement}; that
     * migration runs on upgrade-from-2.8 sites, this private method runs
     * on fresh installs.
     *
     * `userId` is nullable + `SET NULL` so notification history outlives
     * the user — aligns with `project_audit_capture_principle.md` (events
     * outlive entities by design).
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
            'id' => $this->integer()->notNull(),
            'userId' => $this->integer()->null(),
            'notificationType' => $this->string()->notNull(),
            'status' => $this->string(16)->notNull()->defaultValue('sent'),
            'recipientEmail' => $this->string()->null(),
            'siteId' => $this->integer()->null(),
            'subject' => $this->text()->null(),
            'body' => $this->mediumText()->null(),
            'errorMessage' => $this->text()->null(),
            'resentFromId' => $this->integer()->null(),
            'sentAt' => $this->dateTime()->notNull(),
            'PRIMARY KEY([[id]])',
        ]);

        $this->createIndex(null, $table, ['userId', 'notificationType', 'sentAt'], false);
        $this->createIndex(null, $table, ['status', 'sentAt'], false);
        $this->createIndex(null, $table, ['siteId'], false);
        $this->createIndex(null, $table, ['resentFromId'], false);
        $this->addForeignKey(null, $table, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $table, ['userId'], Table::USERS, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $table, ['siteId'], Table::SITES, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $table, ['resentFromId'], $table, ['id'], 'SET NULL', null);
    }

    /**
     * Creates the policies table.
     *
     * Element-backed (Craft 5 idiom): `id` is a FK to `craft_elements.id`
     * with `ON DELETE CASCADE`. Pairs with
     * {@see \craftpulse\passwordpolicy\elements\PolicyElement} and
     * {@see \craftpulse\passwordpolicy\records\PolicyRecord} — the element
     * provides the queryable + index surface, the record stays the storage
     * layer. Mirror of {@see m260513_172440_ConvertPolicyToElement}; that
     * migration runs on upgrade-from-2.10 sites, this private method runs
     * on fresh installs.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createPoliciesTable(): void
    {
        $table = '{{%passwordpolicy_policies}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->integer()->notNull(),
            'name' => $this->string(255)->notNull(),
            'handle' => $this->string(255)->notNull(),
            'preset' => $this->string(64)->null(),
            'settings' => $this->json()->notNull(),
            'sortOrder' => $this->smallInteger()->notNull()->defaultValue(0),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
            'PRIMARY KEY([[id]])',
        ]);

        $this->createIndex(null, $table, ['handle'], true);
        $this->addForeignKey(null, $table, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
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
     * Creates the known-devices table — one row per (user, device
     * fingerprint) that the Feature 1 login listener records on
     * `yii\web\User::EVENT_AFTER_LOGIN`. The fingerprint is a SHA-256 of
     * the request user-agent + masked IP; a login from a fingerprint with
     * no existing row is a "new device", which (on Enterprise +
     * `enableNewDeviceAlerts`) drives the new-device alert email.
     *
     * Capture is universal across editions per memory rule
     * `project_audit_capture_principle.md` — the row is written on Lite /
     * Pro / Enterprise alike; only the alert email and the audit-log
     * exposure are Enterprise-gated. An Enterprise upgrade therefore
     * inherits a populated device history rather than starting blank.
     *
     * Privacy: the raw user-agent and raw IP are NEVER stored. Only the
     * derived fingerprint, the human-readable `deviceLabel` (e.g.
     * "Chrome on macOS"), and the masked IP (last IPv4 octet zeroed /
     * IPv6 truncated to /64) land on the row.
     *
     * `userId` FK CASCADE — device history dies with the user (it is
     * user-scoped device state, not an audit event that must outlive the
     * entity). `siteId` FK SET NULL + nullable — records which site the
     * login happened on for multi-site installs; a deleted site nulls the
     * column rather than cascading the row away.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createKnownDevicesTable(): void
    {
        $table = '{{%passwordpolicy_known_devices}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'fingerprint' => $this->char(64)->notNull(),
            'deviceLabel' => $this->string()->null(),
            'maskedIp' => $this->string(45)->null(),
            'siteId' => $this->integer()->null(),
            'firstSeenAt' => $this->dateTime()->notNull(),
            'lastSeenAt' => $this->dateTime()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['fingerprint'], false);
        $this->createIndex(null, $table, ['lastSeenAt'], false);
        // Unique on (userId, fingerprint) — the upsert key. A device is
        // "new" iff no row matches this pair; the listener inserts on
        // miss and bumps `lastSeenAt` on hit.
        $this->createIndex(null, $table, ['userId', 'fingerprint'], true);

        $this->addForeignKey(null, $table, ['userId'], Table::USERS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $table, ['siteId'], Table::SITES, ['id'], 'SET NULL', null);
    }

    /**
     * Creates the group alert subscriptions table.
     *
     * Backs Feature 3 (per-group alerts, Pro) — one row per (group, event,
     * recipient) routing rule. When a user triggers a `breach_detected` or
     * `new_device` alert, a copy is routed to each enabled subscription
     * whose `groupId` is in the user's RESOLVED group set (per memory rule
     * `project_per_group_resolution_hazard.md` — resolved, never global).
     *
     * `groupId` FKs to `usergroups.id` with `ON DELETE CASCADE` — when an
     * admin deletes a user group, its alert subscriptions are removed
     * automatically (no orphan recipients). Capture/storage is
     * edition-independent; the dispatch that reads these rows is Pro-gated
     * one layer up.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createGroupAlertSubscriptionsTable(): void
    {
        $table = '{{%passwordpolicy_group_alert_subscriptions}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'groupId' => $this->integer()->notNull(),
            'eventType' => $this->string()->notNull(),
            'recipientEmail' => $this->string()->notNull(),
            'enabled' => $this->boolean()->notNull()->defaultValue(true),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['groupId', 'eventType'], false);
        $this->addForeignKey(null, $table, ['groupId'], '{{%usergroups}}', ['id'], 'CASCADE', null);
    }

    /**
     * Creates the API tokens table — the registry of hashed Bearer tokens
     * the Feature 2 read-only REST surface (`ApiController`) authenticates
     * against. Mirror of {@see m260610_180223_AddApiTokensTable}; that
     * migration runs on upgrade-from-2.15 sites, this private method runs
     * on fresh installs.
     *
     * Security: the plaintext token is NEVER persisted. Only its SHA-256
     * `tokenHash` (unique — the lookup key on `findByToken()`) and a short
     * `tokenPrefix` (the first 8 chars, for CP display/identification) land
     * on the row. The plaintext is returned exactly once at issue time and
     * never recoverable thereafter — see
     * {@see \craftpulse\passwordpolicy\services\ApiTokenService::issue()}.
     *
     * The REST surface is an Enterprise-only exposure (matches the existing
     * `apiEnabled` setting). The table exists empty on Lite / Pro and that's
     * the correct state per `project_audit_capture_principle.md` — but
     * unlike the audit tables, NOTHING writes here on sub-editions because
     * the only writer (the CP token manager) is Enterprise-gated.
     *
     * `createdByUserId` FK SET NULL + nullable — a token outlives the admin
     * who issued it (revocation is an explicit operator action, not a
     * cascade off the issuer's deletion). `expiresAt` nullable — null means
     * "no expiry"; `findByToken()` rejects rows whose `expiresAt` is in the
     * past.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createApiTokensTable(): void
    {
        $table = '{{%passwordpolicy_api_tokens}}';

        if ($this->db->tableExists($table)) {
            return;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'name' => $this->string()->notNull(),
            'tokenHash' => $this->char(64)->notNull(),
            'tokenPrefix' => $this->string(16)->notNull(),
            'scopes' => $this->json()->null(),
            'lastUsedAt' => $this->dateTime()->null(),
            'expiresAt' => $this->dateTime()->null(),
            'createdByUserId' => $this->integer()->null(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        // Unique on the hash — the `findByToken()` lookup key and the
        // guarantee that two tokens can't collide on the same digest.
        $this->createIndex(null, $table, ['tokenHash'], true);
        $this->createIndex(null, $table, ['expiresAt'], false);
        $this->addForeignKey(null, $table, ['createdByUserId'], Table::USERS, ['id'], 'SET NULL', null);
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
        // UTC — `dateCreated` / `dateUpdated` are UTC columns. A bare
        // `new \DateTime()` records the site-local wall clock and skews the
        // displayed timestamps on non-UTC installs.
        $now = (new \DateTime('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');

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
