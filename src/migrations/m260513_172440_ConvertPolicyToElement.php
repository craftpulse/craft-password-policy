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

/**
 * Class m260513_172440_ConvertPolicyToElement
 *
 * Converts `passwordpolicy_policies` from a plain record-backed table to
 * an element-backed table — the third (and final) member of the
 * foundation-refactor trio started by
 * `m260511_133103_ConvertNotificationLogToElement` (Step 4) and
 * `m260511_154624_ConvertAuditLogToElement` (Step 5).
 *
 * Shape change:
 *
 *  - Old: `id INT AUTO_INCREMENT PRIMARY KEY` — self-owned identifier.
 *  - New: `id INT NOT NULL PRIMARY KEY` with FK to `craft_elements.id`
 *    ON DELETE CASCADE. The queryable / index surface lives on
 *    `PolicyElement`; the element-record pairing preserves the `id`
 *    column so the existing
 *    `passwordpolicy_policy_groups.policyId → passwordpolicy_policies.id`
 *    CASCADE continues to work.
 *
 * Dependent FKs (`passwordpolicy_policy_groups.policyId → policies.id`
 * + `passwordpolicy_blocklist.policyId → policies.id`) block the
 * column-type rewrite — MySQL refuses an `ALTER TABLE` on a column
 * referenced by another table's FK (error 1833). The migration drops
 * every dependent FK before the primary-key rewrite via an
 * INFORMATION_SCHEMA enumeration of inbound FKs, then re-establishes
 * the canonical shape from `Install.php` after — see
 * `_dropInboundForeignKeys()` + `_ensureDependentForeignKeys()`. The
 * junction is also truncated alongside the policies table (FK CASCADE
 * would handle it, but explicit truncate documents intent).
 *
 * **FK dedup baked in.** Steps 4 + 5 each needed a follow-up commit
 * (`f800d72`) to clean up duplicate FKs the conversions left behind.
 * This migration enumerates every existing FK on `passwordpolicy_policies`
 * via `INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS` and drops each one
 * by name before adding the canonical FK set. No follow-up commit
 * needed.
 *
 * **Migration shape — playground truncation.** This migration runs
 * against the unreleased 5.2.0 schema; the playground holds Step 6
 * test data only. Truncating in `safeUp()` skips the extra code path
 * that would migrate each row into a paired element + record entry,
 * and per the durable rule
 * `feedback_foundation_first_no_refactor_deferrals.md` we only owe
 * post-release operators a row-preserving migration. Documented in the
 * CHANGELOG so 5.2.0-alpha.x → 5.2.0 upgraders aren't surprised.
 *
 * The junction `passwordpolicy_policy_groups` is truncated alongside
 * `passwordpolicy_policies`. The FK CASCADE on `policyId` would handle
 * it implicitly, but the explicit truncate documents intent and avoids
 * relying on MySQL's CASCADE ordering during a primary-key rewrite.
 *
 * **Idempotent.** Re-running on an already-converted DB is a no-op
 * (the FK-to-`craft_elements.id` check matches the new shape and
 * returns early).
 *
 * Pairs with `Install.php::_createPoliciesTable()` — fresh installs land
 * directly on the new shape without running this migration. Schema
 * version bump: 2.10.0 → 2.11.0.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260513_172440_ConvertPolicyToElement extends Migration
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
        $table = '{{%passwordpolicy_policies}}';
        $junction = '{{%passwordpolicy_policy_groups}}';
        $blocklist = '{{%passwordpolicy_blocklist}}';

        // Fail fast on non-MySQL before any partial DDL runs. This
        // conversion's FK-rewrite machinery relies on MySQL-only
        // INFORMATION_SCHEMA extensions (`KEY_COLUMN_USAGE.REFERENCED_*`).
        // A clear early throw beats a cryptic mid-migration SQL error or a
        // silent no-op that leaves the schema half-converted.
        if ($this->db->getDriverName() !== Connection::DRIVER_MYSQL) {
            throw new \RuntimeException(
                'm260513_172440_ConvertPolicyToElement requires MySQL, because its FK rewrite '
                . 'depends on MySQL-only INFORMATION_SCHEMA extensions. PostgreSQL upgraders '
                . 'should land on the converted shape via a fresh install (Install.php) instead.',
            );
        }

        if (!$this->db->tableExists($table)) {
            // Fresh install path — `Install.php` creates the converted
            // shape directly; nothing for this migration to do.
            return true;
        }

        // Idempotent guard. If the FK from `passwordpolicy_policies.id`
        // to `craft_elements.id` already exists, we've already run.
        if ($this->_idHasElementForeignKey($table)) {
            return true;
        }

        // Truncate junction first (FK order matters even though CASCADE
        // would handle it — explicit clears any stray rows the CASCADE
        // wouldn't reach if MySQL re-orders the operations during the
        // primary-key rewrite below).
        $this->db->createCommand()
            ->delete($junction)
            ->execute();

        // Clear per-policy blocklist rows (G6) so dropping the FK to
        // policies.id below doesn't leave dangling references. Global
        // (policyId IS NULL) entries stay — those don't depend on the
        // policies table.
        $this->db->createCommand()
            ->delete($blocklist, ['not', ['policyId' => null]])
            ->execute();

        $this->db->createCommand()
            ->delete($table)
            ->execute();

        // Enumerate every physical FK on the table (raw
        // INFORMATION_SCHEMA — Yii's `TableSchema::foreignKeys` dedupes
        // by column-and-target, hiding duplicates) and drop each by
        // name. The current `passwordpolicy_policies` table has no FKs
        // of its own, but bake the enumeration in defensively so any
        // future column-FK additions don't leave a duplicate behind.
        $this->_dropAllForeignKeysByName($table);

        // Drop every inbound FK pointing at `passwordpolicy_policies`
        // before rewriting the primary key. MySQL refuses to ALTER a
        // column that participates in another table's FK constraint
        // (error 1833). Inbound FKs (junction.policyId,
        // blocklist.policyId) are restored at the end of the rewrite
        // via `_ensureDependentForeignKeys()`.
        $this->_dropInboundForeignKeys($table);

        // Strip AUTO_INCREMENT off the id column BEFORE dropping the
        // primary key. MySQL refuses `DROP PRIMARY KEY` on a table
        // whose sole auto-increment column would be left without an
        // index. After this ALTER, `id` is still NOT NULL but no
        // longer auto-assigned — element ids will be assigned by
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
        // row cascades a drop on the policies row.
        $this->addForeignKey(
            null,
            $table,
            ['id'],
            Table::ELEMENTS,
            ['id'],
            'CASCADE',
            null,
        );

        // Restore canonical dependent FKs from `Install.php` — the
        // junction's FKs into policies + usergroups, and the
        // blocklist's FK into policies. Asserts the shape via
        // INFORMATION_SCHEMA so re-running on a partially-converted
        // DB doesn't duplicate constraints.
        $this->_ensureDependentForeignKeys($junction, $blocklist, $table);

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
        echo "m260513_172440_ConvertPolicyToElement cannot be reverted.\n";

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Enumerates every physical foreign key on `$table` via
     * `INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS` and drops each by
     * name. Necessary because Yii's `TableSchema::foreignKeys` cache
     * dedupes by column-and-target-table; duplicate FKs are invisible
     * to `MigrationHelper::dropAllForeignKeysOnTable()`.
     *
     * `$table` is the Yii-bracketed table name (e.g.
     * `{{%passwordpolicy_policies}}`). The prefix is resolved before
     * the INFORMATION_SCHEMA lookup.
     *
     * @param string $table the bracketed table reference
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dropAllForeignKeysByName(string $table): void
    {
        $db = Craft::$app->getDb();
        $resolvedTable = $db->getSchema()->getRawTableName($table);

        $constraints = (new Query())
            ->select('CONSTRAINT_NAME')
            ->from('INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS')
            ->where([
                'CONSTRAINT_SCHEMA' => $this->_informationSchemaScope(),
                'TABLE_NAME' => $resolvedTable,
            ])
            ->column();

        foreach ($constraints as $name) {
            $this->dropForeignKey($name, $table);
        }
    }

    /**
     * Drops the primary key on a table. MySQL's primary-key drop syntax
     * doesn't require a name — `ALTER TABLE ... DROP PRIMARY KEY` is the
     * canonical form. PostgreSQL names the constraint `<table>_pkey` by
     * convention, dropped via `ALTER TABLE ... DROP CONSTRAINT
     * "<table>_pkey"`. Issue the raw per-driver SQL.
     *
     * @param string $table table reference
     * @return void
     *
     * @throws \RuntimeException on an unsupported driver
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dropPrimaryKey(string $table): void
    {
        $rawName = $this->db->getSchema()->getRawTableName($table);
        $driver = $this->db->getDriverName();

        if ($driver === Connection::DRIVER_MYSQL) {
            $this->execute("ALTER TABLE `{$rawName}` DROP PRIMARY KEY");

            return;
        }

        if ($driver === Connection::DRIVER_PGSQL) {
            $this->execute("ALTER TABLE \"{$rawName}\" DROP CONSTRAINT \"{$rawName}_pkey\"");

            return;
        }

        throw new \RuntimeException("Unsupported database driver for primary-key drop: {$driver}.");
    }

    /**
     * Returns the database name that scopes INFORMATION_SCHEMA lookups to
     * the current connection.
     *
     * MySQL-only by design. The FK enumeration in this migration leans on
     * MySQL extensions to INFORMATION_SCHEMA — `KEY_COLUMN_USAGE`'s
     * `REFERENCED_TABLE_NAME` / `REFERENCED_TABLE_SCHEMA` columns are not in
     * the SQL standard and don't exist on PostgreSQL, where inbound FKs are
     * discovered via `pg_constraint` or `TABLE_CONSTRAINTS` joins instead.
     * `safeUp()` fails fast on non-MySQL drivers before reaching here; this
     * guard is the belt-and-braces second line.
     *
     * @return string the database name to filter on
     *
     * @throws \RuntimeException on a non-MySQL driver
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _informationSchemaScope(): string
    {
        $db = Craft::$app->getDb();

        if ($db->getDriverName() !== Connection::DRIVER_MYSQL) {
            throw new \RuntimeException(
                'm260513_172440_ConvertPolicyToElement requires MySQL, because its FK rewrite '
                . 'depends on MySQL-only INFORMATION_SCHEMA extensions.',
            );
        }

        return (string)$db->createCommand('SELECT DATABASE()')->queryScalar();
    }

    /**
     * Asserts the canonical dependent FKs from `Install.php` are in
     * place after the policies-table primary-key rewrite. The targets
     * are:
     *
     *  - `junction.policyId → policies.id` (CASCADE)
     *  - `junction.groupId → usergroups.id` (CASCADE)
     *  - `blocklist.policyId → policies.id` (CASCADE)
     *
     * Enumerates physical FKs via INFORMATION_SCHEMA so the check sees
     * every constraint (Yii's `TableSchema::foreignKeys` dedupes by
     * column-and-target).
     *
     * @param string $junction the bracketed junction-table reference
     * @param string $blocklist the bracketed blocklist-table reference
     * @param string $policies the bracketed policies-table reference
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _ensureDependentForeignKeys(string $junction, string $blocklist, string $policies): void
    {
        $db = Craft::$app->getDb();
        $resolvedJunction = $db->getSchema()->getRawTableName($junction);
        $resolvedBlocklist = $db->getSchema()->getRawTableName($blocklist);
        $resolvedPolicies = $db->getSchema()->getRawTableName($policies);
        $resolvedUserGroups = $db->getSchema()->getRawTableName(Table::USERGROUPS);

        $rows = (new Query())
            ->select(['k.TABLE_NAME', 'k.COLUMN_NAME', 'k.REFERENCED_TABLE_NAME'])
            ->from(['k' => 'INFORMATION_SCHEMA.KEY_COLUMN_USAGE'])
            ->where([
                'k.TABLE_SCHEMA' => $this->_informationSchemaScope(),
                'k.TABLE_NAME' => [$resolvedJunction, $resolvedBlocklist],
            ])
            ->andWhere(['is not', 'k.REFERENCED_TABLE_NAME', null])
            ->all();

        $hasJunctionPolicyFk = false;
        $hasJunctionGroupFk = false;
        $hasBlocklistPolicyFk = false;

        foreach ($rows as $row) {
            if (
                $row['TABLE_NAME'] === $resolvedJunction
                && $row['COLUMN_NAME'] === 'policyId'
                && $row['REFERENCED_TABLE_NAME'] === $resolvedPolicies
            ) {
                $hasJunctionPolicyFk = true;
            }
            if (
                $row['TABLE_NAME'] === $resolvedJunction
                && $row['COLUMN_NAME'] === 'groupId'
                && $row['REFERENCED_TABLE_NAME'] === $resolvedUserGroups
            ) {
                $hasJunctionGroupFk = true;
            }
            if (
                $row['TABLE_NAME'] === $resolvedBlocklist
                && $row['COLUMN_NAME'] === 'policyId'
                && $row['REFERENCED_TABLE_NAME'] === $resolvedPolicies
            ) {
                $hasBlocklistPolicyFk = true;
            }
        }

        if (!$hasJunctionPolicyFk) {
            $this->addForeignKey(null, $junction, ['policyId'], $policies, ['id'], 'CASCADE', null);
        }

        if (!$hasJunctionGroupFk) {
            $this->addForeignKey(null, $junction, ['groupId'], Table::USERGROUPS, ['id'], 'CASCADE', null);
        }

        if (!$hasBlocklistPolicyFk) {
            $this->addForeignKey(null, $blocklist, ['policyId'], $policies, ['id'], 'CASCADE', null);
        }
    }

    /**
     * Drops every inbound FK targeting `$table` (rows where the FK's
     * referenced table matches `$table`). Used to clear the way for an
     * `ALTER TABLE` on `$table.id` — MySQL refuses to ALTER a column
     * referenced by another table's FK (error 1833).
     *
     * Enumerates via `INFORMATION_SCHEMA.KEY_COLUMN_USAGE` so duplicate
     * FKs (the gotcha Steps 4 + 5 hit) are all visible.
     *
     * @param string $table the bracketed table reference whose inbound
     *     FKs to drop (e.g. `{{%passwordpolicy_policies}}`)
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dropInboundForeignKeys(string $table): void
    {
        $db = Craft::$app->getDb();
        $scope = $this->_informationSchemaScope();
        $resolvedTable = $db->getSchema()->getRawTableName($table);

        $rows = (new Query())
            ->select(['CONSTRAINT_NAME', 'TABLE_NAME'])
            ->from('INFORMATION_SCHEMA.KEY_COLUMN_USAGE')
            ->where([
                'TABLE_SCHEMA' => $scope,
                'REFERENCED_TABLE_SCHEMA' => $scope,
                'REFERENCED_TABLE_NAME' => $resolvedTable,
            ])
            ->all();

        foreach ($rows as $row) {
            // dropForeignKey requires the bracketed table reference;
            // re-bracket the raw name we get back from the query.
            $bracketedSource = '{{%' . substr($row['TABLE_NAME'], strlen($db->tablePrefix)) . '}}';
            $this->dropForeignKey($row['CONSTRAINT_NAME'], $bracketedSource);
        }
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
