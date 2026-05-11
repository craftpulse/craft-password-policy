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
 * Class m260511_133103_ConvertNotificationLogToElement
 *
 * Converts `passwordpolicy_notification_log` from a plain record-backed
 * table to an element-backed table. The shape change:
 *
 *  - Old: `id INT AUTO_INCREMENT PRIMARY KEY` — self-owned identifier.
 *  - New: `id INT NOT NULL PRIMARY KEY` with FK to `craft_elements.id`
 *    ON DELETE CASCADE — every row pairs with a Craft element. Element
 *    soft-delete (via `dateDeleted` on `craft_elements`) becomes the
 *    boundary; hard-delete cascades to drop the notification log row.
 *
 *  - The `userId` FK shifts from `ON DELETE CASCADE` to `ON DELETE SET
 *    NULL` so the audit trail outlives the user. Hard-deleting a user
 *    now leaves their notification history visible (with userId = NULL)
 *    rather than wiping the rows. Aligns with the
 *    `project_audit_capture_principle.md` rule that events outlive
 *    entities by design.
 *
 *  - The `userId` column flips to nullable for the same reason.
 *
 * **Migration shape — playground truncation.** This migration runs
 * against the unreleased 5.2.0 schema; the playground holds Phase F2
 * activity-surface test data only. Truncating in `safeUp()` skips the
 * extra code path that would migrate each row into a paired element +
 * record entry, and per the durable rule
 * `feedback_foundation_first_no_refactor_deferrals.md` we only owe
 * post-release operators a row-preserving migration. Documented in the
 * CHANGELOG so 5.2.0-alpha.x → 5.2.0 upgraders aren't surprised.
 *
 * **Idempotent.** Re-running on an already-converted DB is a no-op
 * (the column-type check matches the new shape and returns early).
 *
 * Pairs with `Install.php::_createNotificationLogTable()` — fresh
 * installs land directly on the new shape without running this
 * migration. Schema version bump: 2.8.0 → 2.9.0.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260511_133103_ConvertNotificationLogToElement extends Migration
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
        $table = '{{%passwordpolicy_notification_log}}';

        if (!$this->db->tableExists($table)) {
            // Fresh install path — `Install.php` creates the converted
            // shape directly; nothing for this migration to do.
            return true;
        }

        // Idempotent guard. If the FK from `passwordpolicy_notification_log.id`
        // to `craft_elements.id` already exists, we've already run.
        if ($this->_idHasElementForeignKey($table)) {
            return true;
        }

        // Truncate existing rows. Playground test data only — 5.2.0 is
        // unreleased; we don't owe pre-release alpha operators a row-
        // preserving migration per the durable rule
        // `feedback_foundation_first_no_refactor_deferrals.md`. Migrating
        // each row into a paired element + record entry would be extra
        // code for no benefit (the data wasn't released).
        $this->db->createCommand()
            ->delete($table)
            ->execute();

        // Drop the self-FK on resentFromId first — it references the
        // primary key column we're about to rewrite.
        $this->_dropForeignKeyByColumn($table, 'resentFromId');

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
        // This is the new boundary: element soft-delete leaves the row
        // visible (filter on dateDeleted IS NULL); element hard-delete
        // cascades a drop.
        $this->addForeignKey(
            null,
            $table,
            ['id'],
            Table::ELEMENTS,
            ['id'],
            'CASCADE',
            null,
        );

        // Restore the self-FK on resentFromId now that the primary key
        // is back in place. Same SET NULL semantics — when a referenced
        // row is hard-deleted, the chain pointer NULLs out rather than
        // cascading.
        $this->addForeignKey(
            null,
            $table,
            ['resentFromId'],
            $table,
            ['id'],
            'SET NULL',
            null,
        );

        // Flip userId from `CASCADE` to `SET NULL` + nullable so the
        // notification history outlives the user. Aligns with the
        // `project_audit_capture_principle.md` rule that events outlive
        // entities by design.
        $this->_dropForeignKeyByColumn($table, 'userId');
        $this->alterColumn($table, 'userId', $this->integer()->null());
        $this->addForeignKey(
            null,
            $table,
            ['userId'],
            Table::USERS,
            ['id'],
            'SET NULL',
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
        echo "m260511_133103_ConvertNotificationLogToElement cannot be reverted.\n";

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Drops any foreign-key constraint on a column. Walks the schema for
     * the constraint name (constraint names are hashed; we can't
     * hardcode them).
     *
     * @param string $table table reference (e.g. `{{%passwordpolicy_notification_log}}`)
     * @param string $column column whose FK should be dropped
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dropForeignKeyByColumn(string $table, string $column): void
    {
        $schema = $this->db->getTableSchema($table);

        if ($schema === null) {
            return;
        }

        foreach ($schema->foreignKeys as $name => $reference) {
            // $reference is [referencedTable, localColumn => referencedColumn, ...]
            unset($reference[0]);
            if (array_key_exists($column, $reference)) {
                $this->dropForeignKey($name, $table);
            }
        }
    }

    /**
     * Drops the primary key on a table. Walks the schema for the
     * primary-key constraint name (`Schema::getTableSchema()` doesn't
     * expose it directly on MySQL; the constraint is just the column
     * list under `primaryKey`).
     *
     * MySQL's primary-key drop syntax doesn't require a name — `ALTER
     * TABLE ... DROP PRIMARY KEY` is the canonical form. Yii's
     * `dropPrimaryKey()` requires a name parameter, so pass an empty
     * string; Yii's MySQL `QueryBuilder` ignores the name in that case.
     * PostgreSQL: the constraint is named `<table>_pkey` by convention
     * — same dropPrimaryKey call with the right name works there too;
     * the project ships MySQL playground only for 5.2.0.
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
