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
 * Class m260507_132250_AddSiemForwardersTable
 *
 * Phase G — G8. Adds the `passwordpolicy_siem_forwarders` table — the
 * registry of SIEM endpoints the plugin forwards audit-log rows to.
 *
 * Schema (per § 3 of the Phase G plan, locked):
 *
 *  - `id` — primary key.
 *  - `name` — admin-supplied display label (nullable).
 *  - `protocol` — forwarder protocol; `'syslog-tls'` is the only value
 *    in 5.2.0. UDP was cut from the matrix entirely (unreliable for
 *    audit forwarding); webhook ships separately as G9 with its own
 *    `passwordpolicy_webhook_endpoints` table. Stored as a plain
 *    string column so 5.3 can join additional syslog variants without
 *    a schema migration.
 *  - `host`, `port` — TCP destination.
 *  - `tlsCertVerify` — bool, defaults true. Operators with self-signed
 *    chains can opt out per-forwarder.
 *  - `tlsCaBundlePath` — env-var-resolved CA bundle path (nullable).
 *    Resolved at use via `App::parseEnv()` in `SiemService::forward()`.
 *  - `eventClasses` — JSON array, nullable. When non-null + non-empty,
 *    overrides the global `siemForwardEventClasses` setting per
 *    forwarder. NULL means "use the global setting."
 *  - `enabled` — bool.
 *  - `circuitOpenAt` — datetime, nullable. Set when the consecutive-
 *    failure threshold opens the circuit; cleared on successful
 *    forward.
 *  - `consecutiveFailures` — int, defaults 0. Durable mirror of the
 *    cache-resident counter in
 *    `pp:siem-forwarder-circuit:{forwarderId}` so a cache flush
 *    doesn't reset circuit state.
 *  - Standard Craft `dateCreated` / `dateUpdated` / `uid` columns.
 *
 * No FK constraints — the forwarder is independent of any Craft entity
 * (sites, users, groups). Deleting any of those does not cascade here.
 *
 * Idempotent — guarded by `tableExists()` so a re-run on a fully-applied
 * DB is a no-op (`migrations.md` rule).
 *
 * Capture is universal per memory rule
 * `project_audit_capture_principle.md`. Audit row writes happen on every
 * edition (G1 ships `forwardedAt` + `forwardAttempts` columns + index
 * unconditionally on the audit_log table). The forwarder *registry* is
 * exposure — only Enterprise installs see the CP subnav, can register
 * forwarders, and run the queue job that consumes them. This table
 * exists empty on Lite / Pro and that's the correct state.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260507_132250_AddSiemForwardersTable extends Migration
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
        $table = '{{%passwordpolicy_siem_forwarders}}';

        if ($this->db->tableExists($table)) {
            return true;
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

        // `enabled` is the hot path for the queue job's
        // `getActiveForwarders()` query; index it so a Pro install with
        // many disabled forwarders doesn't full-scan.
        $this->createIndex(null, $table, ['enabled'], false);
        $this->createIndex(null, $table, ['circuitOpenAt'], false);

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
        echo "m260507_132250_AddSiemForwardersTable cannot be reverted.\n";

        return false;
    }
}
