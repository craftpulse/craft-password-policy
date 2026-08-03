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
 * Class m260610_141354_AddGeoColumnsToAuditLog
 *
 * Feature 4 (IP geolocation). Adds two nullable geolocation columns to
 * `passwordpolicy_audit_log`:
 *
 *  - `geoCountry` — `CHAR(2) NULL`. ISO 3166-1 alpha-2 country code (e.g.
 *    `US`) resolved from the request IP via the bundled DB-IP Lite
 *    database. Stores ONLY the country code — never the raw IP.
 *  - `geoRegion` — `VARCHAR(255) NULL`. Subdivision / region name. The
 *    bundled DB-IP Lite database is country-level, so this is almost
 *    always NULL; the column exists so a future city-level database
 *    populates it without a follow-up migration.
 *
 * **Both columns are EXCLUDED from the hash-chain canonical payload.**
 * `AuditLogService::canonicalize()` hashes a fixed key set
 * (`changedByUserId, dateCreated, details, event, ipHash, outcome,
 * source, uid, userId, userIdentifier`); geo is not in it. Existing chain
 * hashes stay reproducible and `password-policy/audit/verify` keeps
 * passing — geo is post-insert enrichment metadata, the same exclusion
 * class as `forwardedAt` / `forwardAttempts`.
 *
 * Capture is universal — the columns land on every edition
 * (`project_audit_capture_principle.md`). Whether they're POPULATED is
 * gated at the `AuditLogService::logEvent()` call site on Enterprise +
 * `geoIpEnabled`; the schema is edition-independent.
 *
 * Idempotent — each add is guarded by `columnExists()`, so a re-run on a
 * fully-applied DB is a no-op. Mirrors the canonical schema in
 * {@see Install::_createAuditLogTable()}.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260610_141354_AddGeoColumnsToAuditLog extends Migration
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
        $table = '{{%passwordpolicy_audit_log}}';

        if (!$this->db->columnExists($table, 'geoCountry')) {
            $this->addColumn(
                $table,
                'geoCountry',
                $this->char(2)->null()->after('userIdentifier'),
            );
        }

        if (!$this->db->columnExists($table, 'geoRegion')) {
            $this->addColumn(
                $table,
                'geoRegion',
                $this->string()->null()->after('geoCountry'),
            );
        }

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
        $table = '{{%passwordpolicy_audit_log}}';

        if ($this->db->columnExists($table, 'geoRegion')) {
            $this->dropColumn($table, 'geoRegion');
        }

        if ($this->db->columnExists($table, 'geoCountry')) {
            $this->dropColumn($table, 'geoCountry');
        }

        return true;
    }
}
