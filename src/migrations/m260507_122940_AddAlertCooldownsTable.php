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

use craft\db\Migration;

/**
 * Class m260507_122940_AddAlertCooldownsTable
 *
 * Phase G — G7. Adds the `passwordpolicy_alert_cooldowns` table — durable
 * storage for the per-(eventClass, cooldownKey) suppression record that
 * `AlertCooldownService` maintains. Two storage surfaces emerge once this
 * lands: `notification_log` (what was sent + when + with what subject /
 * body) and `alert_cooldowns` (when alerting fired regardless of whether
 * an email or row was emitted). An auditor asking "you had a credential-
 * stuffing burst on 2026-05-04 — show me the alert suppression record"
 * needs the row to be on disk, not in cache; that's the durable-storage
 * decision the table embodies (memory rule
 * `project_audit_capture_principle.md`).
 *
 * Schema:
 *
 *  - `id` — primary key.
 *  - `eventClass` — string, indexed. Logical alert type (e.g.
 *    `expiry_reminder`, `admin_security_alert:hibp_breach_detected`,
 *    `hibp_login_burst`).
 *  - `cooldownKey` — string, indexed. The dedup key shape (e.g.
 *    `user:<userId>`, `event:<event>`, `prefix:<5-char-sha1>`).
 *  - `firedAt` — datetime, indexed. UTC timestamp of the fire.
 *  - Composite index on `(eventClass, cooldownKey, firedAt)` — that's
 *    the dedup query path
 *    (`WHERE eventClass = ? AND cooldownKey = ? AND firedAt >= ?`).
 *  - Standard Craft `dateCreated` / `dateUpdated` / `uid` columns to
 *    match the rest of the plugin schema.
 *
 * No FK constraints — events outlive entities by design. A deleted user's
 * cooldown rows still answer "did we suppress an alert at the time?" for
 * auditors after the user is gone.
 *
 * Idempotent — guarded by `tableExists()` so a re-run on a fully-applied
 * DB is a no-op. Same idiom as
 * {@see m260430_170841_AddNotificationTemplatesTable}.
 *
 * Capture is universal per memory rule
 * `project_audit_capture_principle.md` — every edition writes cooldown
 * rows. Edition gates would only apply to read surfaces, and there are
 * no read surfaces in G7 itself (G8's SIEM forwarder reads cooldowns for
 * its circuit-breaker; that's an Enterprise consumer of universal data,
 * not an edition gate on the writes here).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260507_122940_AddAlertCooldownsTable extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        $table = '{{%passwordpolicy_alert_cooldowns}}';

        if ($this->db->tableExists($table)) {
            return true;
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

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeDown(): bool
    {
        echo "m260507_122940_AddAlertCooldownsTable cannot be reverted.\n";

        return false;
    }
}
