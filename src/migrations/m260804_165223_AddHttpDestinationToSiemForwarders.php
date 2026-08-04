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

use craft\db\Migration;

/**
 * Class m260804_165223_AddHttpDestinationToSiemForwarders
 *
 * Adds the HTTP destination columns to `passwordpolicy_siem_forwarders`,
 * plus the syslog `framing` column.
 *
 * Until now `protocol` accepted exactly one value (`syslog-tls`) and the
 * table carried no URL at all, so a SIEM that ingests over HTTPS was
 * unreachable without the operator writing their own relay. The four
 * columns below are what a forwarder needs to POST an audit row to an
 * HTTPS collector:
 *
 *  - `url` — the destination URL (2048 chars, matching the webhook
 *    endpoints table). Nullable, because a syslog forwarder has none.
 *    Accepts an env-var reference, resolved at forward time.
 *  - `authType` — `none`, `bearer`, or `basic`. Not null with a `none`
 *    default so every existing syslog row lands on a meaningful value
 *    without a backfill.
 *  - `authToken` — the credential, encrypted at rest at the model
 *    boundary. `text` rather than `string` for the same reason the
 *    webhook endpoints table stores `secretCurrent` as `text`: Craft's
 *    `Security::encryptByKey()` output is base64-wrapped ciphertext,
 *    whose length isn't bounded by the plaintext's.
 *  - `headers` — JSON map of extra request headers, for the vendor
 *    header schemes a generic auth type can't express (`DD-API-KEY`,
 *    `Authorization: Splunk <token>`).
 *
 * `host` and `port` are relaxed to nullable in the same pass. They are
 * the syslog transport's address and an HTTP forwarder has neither; the
 * model requires them conditionally on `protocol` instead. Existing rows
 * keep their values, so nothing is lost.
 *
 * `framing` is the fifth column. RFC 5425 §4.3.1 makes octet counting a
 * MUST for a syslog-over-TLS transport receiver, so that is the column
 * default for every row; `newline` is the operator-facing alternative for
 * a receiver that wants RFC 6587-style delimiting instead, which is what
 * rsyslog's `imtcp` accepts by default. No backfill: the forwarder
 * surface has never shipped, so there is no configured receiver anywhere
 * whose framing an upgrade could change.
 *
 * No new index. Neither `protocol` nor any column added here appears in
 * the `getActiveForwarders()` predicate, and the table is a small
 * operator-managed registry.
 *
 * Idempotent — every add is guarded by a column-existence check and each
 * relax by an `allowNull` check, so a re-run on a fully-applied DB is a
 * no-op (`migrations.md` rule). Mirrors the same column set in
 * `Install::_createSiemForwardersTable()`; that private method runs on
 * fresh installs, this migration runs on installs already carrying the
 * table.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260804_165223_AddHttpDestinationToSiemForwarders extends Migration
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

        // `Install::safeUp()` runs earlier in the chain and creates the
        // table already carrying these columns, so on a fresh install
        // there is nothing to add here.
        if (!$this->db->tableExists($table)) {
            return true;
        }

        $schema = $this->db->getTableSchema($table, true);

        if ($schema === null) {
            return true;
        }

        if ($schema->getColumn('url') === null) {
            $this->addColumn($table, 'url', $this->string(2048)->null());
        }

        if ($schema->getColumn('authType') === null) {
            $this->addColumn($table, 'authType', $this->string(32)->notNull()->defaultValue('none'));
        }

        if ($schema->getColumn('authToken') === null) {
            $this->addColumn($table, 'authToken', $this->text()->null());
        }

        if ($schema->getColumn('headers') === null) {
            $this->addColumn($table, 'headers', $this->json()->null());
        }

        if ($schema->getColumn('framing') === null) {
            $this->addColumn($table, 'framing', $this->string(32)->notNull()->defaultValue('octet-counted'));
        }

        // Relax the syslog address. An HTTP forwarder carries neither, and
        // `SiemForwarderModel` requires each one only when the protocol is
        // the syslog transport.
        $host = $schema->getColumn('host');

        if ($host !== null && !$host->allowNull) {
            $this->alterColumn($table, 'host', $this->string()->null());
        }

        $port = $schema->getColumn('port');

        if ($port !== null && !$port->allowNull) {
            $this->alterColumn($table, 'port', $this->integer()->null());
        }

        $this->db->getSchema()->refresh();

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
        echo "m260804_165223_AddHttpDestinationToSiemForwarders cannot be reverted.\n";

        return false;
    }
}
