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

use craft\db\Connection;
use craft\db\Migration;
use craft\db\Table;
use craftpulse\passwordpolicy\enums\ChangeReason;

/**
 * m260502_214932_AddAuditShapeToPasswordHistory migration.
 *
 * Phase D0 audit-shape foundation. Adds the audit-trail columns to
 * `passwordpolicy_password_history` and creates the new
 * `passwordpolicy_user_state` table that tracks pending-reset reasons +
 * breach detection state per user. Both surfaces are populated on every
 * edition; gates apply to UI / API / SIEM exposure, not to the schema or
 * service write path (memory rule `project_audit_capture_principle.md`).
 *
 * **changeReason column type — single source of truth.** The PHP enum
 * `ChangeReason` drives the column-value list. The migration reads
 * `ChangeReason::values()` at runtime and emits a MySQL `ENUM(...)` /
 * PostgreSQL `VARCHAR + CHECK IN (...)` clause from it. **Adding a case
 * to the enum requires a follow-up migration** that runs `ALTER TABLE`
 * with the extended value list — forgetting surfaces as a SQL error on
 * the first INSERT, not at deploy time.
 *
 * Idempotency: every column add and table create is guarded by
 * `columnExists` / `tableExists`. Re-runs are no-ops.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260502_214932_AddAuditShapeToPasswordHistory extends Migration
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
        $this->_addAuditColumnsToPasswordHistory();
        $this->_createUserStateTable();

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
        echo "m260502_214932_AddAuditShapeToPasswordHistory cannot be reverted.\n";
        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Adds the five audit columns to `passwordpolicy_password_history`:
     * `changedByUserId`, `changeReason`, `changeSourceIp`,
     * `changeUserAgent`, `policySnapshot`. Plus an index on
     * `changedByUserId` for "show me changes by admin X" queries.
     *
     * Each column add is guarded by `columnExists` so re-runs are safe.
     * The `changedByUserId` FK is `SET NULL` on delete — when an admin
     * is deleted, the history rows persist but lose attribution. Matches
     * the audit-log table's behavior for the same column.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _addAuditColumnsToPasswordHistory(): void
    {
        $table = '{{%passwordpolicy_password_history}}';

        if (!$this->db->columnExists($table, 'changedByUserId')) {
            $this->addColumn($table, 'changedByUserId', $this->integer()->null()->after('userId'));
            $this->createIndex(null, $table, ['changedByUserId'], false);
            $this->addForeignKey(
                null,
                $table,
                ['changedByUserId'],
                Table::USERS,
                ['id'],
                'SET NULL',
                null,
            );
        }

        if (!$this->db->columnExists($table, 'changeReason')) {
            $this->addColumn(
                $table,
                'changeReason',
                $this->_changeReasonColumnType(
                    columnName: 'changeReason',
                    notNull: true,
                    defaultValue: ChangeReason::SelfService->value,
                ),
            );
        }

        if (!$this->db->columnExists($table, 'changeSourceIp')) {
            $this->addColumn($table, 'changeSourceIp', $this->string(45)->null());
        }

        if (!$this->db->columnExists($table, 'changeUserAgent')) {
            $this->addColumn($table, 'changeUserAgent', $this->text()->null());
        }

        if (!$this->db->columnExists($table, 'policySnapshot')) {
            $this->addColumn($table, 'policySnapshot', $this->string(64)->null());
        }
    }

    /**
     * Creates the per-user state table tracking pending-reset reasons +
     * breach state. One sparsely-populated row per user, FK CASCADE to
     * users so the row goes when the user is deleted (no orphan rows
     * to GC).
     *
     * The `pendingResetReason` column reuses the same cross-DB-safe
     * column type as `changeReason` — but nullable with no default
     * (null = "no pending reset").
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
     * Returns the cross-DB column-type clause for `changeReason`-shaped
     * columns. Single source of truth = the PHP enum. MySQL gets a real
     * `ENUM(...)` (best-of-breed for fixed value lists). PostgreSQL gets
     * `VARCHAR(32) + CHECK (col IN (...))` — same constraint shape, no
     * `CREATE TYPE` ceremony. SQLite (used in some test envs) falls back
     * to plain `VARCHAR(32)` with no constraint — the application layer
     * is the type guarantor on SQLite.
     *
     * Adding a new enum case requires a follow-up migration that runs
     * `ALTER TABLE ... MODIFY changeReason ENUM(...)` (MySQL) or drops
     * and recreates the CHECK constraint (PostgreSQL) with the extended
     * value list.
     *
     * @param string $columnName used in the PostgreSQL CHECK clause; the
     *     same function is reused for `changeReason` and
     *     `pendingResetReason` columns
     * @param bool $notNull when true, the clause adds `NOT NULL`
     * @param string|null $defaultValue when set, adds `DEFAULT '...'`;
     *     null skips the default clause entirely (so PostgreSQL doesn't
     *     reject `DEFAULT NULL` against a NOT NULL column)
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
}
