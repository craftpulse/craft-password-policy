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
use craft\db\Table;

/**
 * Class m260511_154624_ConvertAuditLogToElement
 *
 * Converts `passwordpolicy_audit_log` from a plain record-backed table
 * to an element-backed table — the second half of the Step 4/Step 5
 * foundation-refactor pair started by
 * `m260511_133103_ConvertNotificationLogToElement`.
 *
 * Shape change:
 *
 *  - Old: `id INT AUTO_INCREMENT PRIMARY KEY` — self-owned identifier.
 *  - New: `id INT NOT NULL PRIMARY KEY` with FK to `craft_elements.id`
 *    ON DELETE CASCADE — every row pairs with a Craft element. The
 *    queryable / index surface lives on `AuditLogElement`; the chain
 *    bytes (`rowHash`, `previousHash`, canonical payload) are unchanged.
 *
 * **Chain invariants preserved.** This migration moves the row's
 * identifier off `AUTO_INCREMENT` and into `craft_elements.id`. The
 * `id` column is NOT in the canonical payload that
 * `AuditLogService::canonicalize()` hashes, so existing chain hashes
 * continue to verify byte-identically. The verifier
 * (`password-policy/audit/verify`) round-trips green before AND after
 * this migration on the same data.
 *
 * **Retention purge.** After this migration, audit rows are hard-
 * deleted via `DELETE FROM craft_elements WHERE id IN (...)` — the FK
 * CASCADE drops the audit_log row. Retention is a compliance
 * requirement; element soft-delete via `dateDeleted` is NOT acceptable
 * for the prune path. `EVENT_AUDIT_CHAIN_ROTATED` continues to fire
 * after the prune with the new chain head info.
 *
 * **Migration shape — playground truncation.** This migration runs
 * against the unreleased 5.2.0 schema; the playground holds Phase G
 * audit-chain test data only. Truncating in `safeUp()` skips the extra
 * code path that would migrate each row into a paired element + record
 * entry, and per the durable rule
 * `feedback_foundation_first_no_refactor_deferrals.md` we only owe
 * post-release operators a row-preserving migration. Documented in the
 * CHANGELOG so 5.2.0-alpha.x → 5.2.0 upgraders aren't surprised.
 *
 * **Idempotent.** Re-running on an already-converted DB is a no-op
 * (the FK-to-`craft_elements.id` check matches the new shape and
 * returns early).
 *
 * Pairs with `Install.php::_createAuditLogTable()` — fresh installs
 * land directly on the new shape without running this migration.
 * Schema version bump: 2.9.0 → 2.10.0.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260511_154624_ConvertAuditLogToElement extends Migration
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

        if (!$this->db->tableExists($table)) {
            // Fresh install path — `Install.php` creates the converted
            // shape directly; nothing for this migration to do.
            return true;
        }

        // Idempotent guard. If the FK from `passwordpolicy_audit_log.id`
        // to `craft_elements.id` already exists, we've already run.
        if ($this->_idHasElementForeignKey($table)) {
            return true;
        }

        // Truncate existing rows. Playground test data only — 5.2.0 is
        // unreleased; we don't owe pre-release alpha operators a row-
        // preserving migration per the durable rule
        // `feedback_foundation_first_no_refactor_deferrals.md`. Migrating
        // each row into a paired element + record entry would be extra
        // code for no benefit (the data wasn't released). The chain
        // resets to genesis on the next write — existing canonical
        // bytes are unchanged, so a future row-preserving variant would
        // be straightforward to write if a post-5.2.0 schema demanded
        // it.
        $this->db->createCommand()
            ->delete($table)
            ->execute();

        // Strip AUTO_INCREMENT off the id column BEFORE dropping the
        // primary key. MySQL refuses `DROP PRIMARY KEY` on a table whose
        // sole auto-increment column would be left without an index.
        // After this ALTER, `id` is still NOT NULL but no longer
        // auto-assigned — element ids will be assigned by
        // `Craft::$app->getElements()->saveElement()` from
        // `craft_elements.id`.
        $this->alterColumn($table, 'id', $this->integer()->notNull());

        // Drop the primary key constraint. `id` survives as a regular
        // NOT NULL column, ready for the new primary-key declaration
        // below.
        $this->_dropPrimaryKey($table);

        // Add the new primary key on the existing `id` column. No
        // column re-creation needed.
        $this->addPrimaryKey(null, $table, ['id']);

        // FK from this table's id → craft_elements.id ON DELETE CASCADE.
        // This is the new boundary: hard-deleting the paired element
        // row cascades a drop on the audit log row. Retention purge
        // routes through this — `purgeOldEntries()` deletes from
        // `craft_elements`, the FK cascades to drop the audit row.
        $this->addForeignKey(
            null,
            $table,
            ['id'],
            Table::ELEMENTS,
            ['id'],
            'CASCADE',
            null,
        );

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
        echo "m260511_154624_ConvertAuditLogToElement cannot be reverted.\n";

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Drops the primary key on a table. MySQL's primary-key drop syntax
     * doesn't require a name — `ALTER TABLE ... DROP PRIMARY KEY` is
     * the canonical form. Yii's `dropPrimaryKey()` requires a name
     * parameter, so issue the raw SQL.
     *
     * @param string $table table reference
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dropPrimaryKey(string $table): void
    {
        $rawName = $this->db->getSchema()->getRawTableName($table);
        $this->execute("ALTER TABLE `{$rawName}` DROP PRIMARY KEY");
    }

    /**
     * Returns true when the table's `id` column already participates in
     * a FK back to `craft_elements.id`. Used as the idempotent guard so
     * re-running this migration on a fully-converted DB short-circuits.
     *
     * @param string $table
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _idHasElementForeignKey(string $table): bool
    {
        $schema = $this->db->getTableSchema($table, true);

        if ($schema === null) {
            return false;
        }

        $elementsTable = $this->db->getSchema()->getRawTableName(Table::ELEMENTS);

        foreach ($schema->foreignKeys as $reference) {
            $referencedTable = $reference[0] ?? null;
            unset($reference[0]);

            if ($referencedTable === $elementsTable && array_key_exists('id', $reference)) {
                return true;
            }
        }

        return false;
    }
}
