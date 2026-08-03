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

/**
 * m260513_142613_DeduplicateElementTableForeignKeys migration.
 *
 * Drops redundant foreign keys left behind by the Step 4
 * (`ConvertNotificationLogToElement`) and Step 5
 * (`ConvertAuditLogToElement`) migrations, then re-adds the canonical
 * FK set per `Install.php`'s fresh-install shape.
 *
 * Root cause: F2's original notification_log + G1's original audit_log
 * tables shipped with FKs on `userId` (CASCADE), `siteId` (SET NULL),
 * `resentFromId` (SET NULL), `changedByUserId` (SET NULL). When Steps 4
 * + 5 added the `id → craft_elements.id` FK and flipped `userId` to
 * SET NULL (per `project_audit_capture_principle.md` — events outlive
 * entities), the new FKs were ADDED via `addForeignKey()` but the
 * original FKs were not DROPPED. `INFORMATION_SCHEMA.KEY_COLUMN_USAGE`
 * on a post-Step-5 install shows two FK entries per column on both
 * tables (8 redundant constraints total).
 *
 * Why this migration uses raw information_schema enumeration instead
 * of `MigrationHelper::dropAllForeignKeysOnTable()`: Yii's
 * `TableSchema::foreignKeys` array dedupes by column-and-referenced-
 * table, so when two FK constraints reference the same column on the
 * same target table, the schema cache only exposes one of them.
 * `dropAllForeignKeysOnTable` walks that deduped collection and only
 * drops one of each pair. The raw information_schema query sees every
 * physical constraint independently and lets us drop them all
 * unambiguously.
 *
 * Runs on MySQL and PostgreSQL alike. The enumeration reads the ANSI
 * `information_schema.table_constraints` view rather than MySQL's extended
 * `referential_constraints`; see `_dropAllForeignKeysByName()` for why the
 * distinction is load-bearing.
 *
 * Functional impact of the duplicates: cosmetic on read; minor
 * write-path overhead from MySQL evaluating redundant constraints
 * per INSERT/UPDATE/DELETE. Not a correctness bug. Cleaning up to
 * prevent future migration code paths from hitting "constraint
 * already exists" errors on a dirty schema.
 *
 * Fresh installs (`Install.php`) are unaffected — they already produce
 * the canonical shape. This migration only normalises upgrade-path
 * installs that came through Step 4 + Step 5 sequentially.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260513_142613_DeduplicateElementTableForeignKeys extends Migration
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
        $auditLog = '{{%passwordpolicy_audit_log}}';
        $notificationLog = '{{%passwordpolicy_notification_log}}';

        // Guard each table independently. A fresh install never created
        // the pre-conversion shape, so the table may be absent (or already
        // canonical) when this normaliser runs out of band.
        if ($this->db->tableExists($auditLog)) {
            $this->_dropAllForeignKeysByName($auditLog);

            // audit_log: id → elements (CASCADE), userId + changedByUserId → users (SET NULL).
            $this->addForeignKey(null, $auditLog, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
            $this->addForeignKey(null, $auditLog, ['userId'], Table::USERS, ['id'], 'SET NULL', null);
            $this->addForeignKey(null, $auditLog, ['changedByUserId'], Table::USERS, ['id'], 'SET NULL', null);
        }

        if ($this->db->tableExists($notificationLog)) {
            $this->_dropAllForeignKeysByName($notificationLog);

            // notification_log: id → elements (CASCADE), userId → users (SET NULL),
            // siteId → sites (SET NULL), resentFromId → self (SET NULL).
            $this->addForeignKey(null, $notificationLog, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
            $this->addForeignKey(null, $notificationLog, ['userId'], Table::USERS, ['id'], 'SET NULL', null);
            $this->addForeignKey(null, $notificationLog, ['siteId'], Table::SITES, ['id'], 'SET NULL', null);
            $this->addForeignKey(null, $notificationLog, ['resentFromId'], $notificationLog, ['id'], 'SET NULL', null);
        }

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeDown(): bool
    {
        // Cannot meaningfully revert — restoring the duplicate state would
        // re-create the constraint mess the up migration cleaned up.
        // Matches the non-revertable contract of the element conversions
        // (`m260511_133103`, `m260511_154624`, `m260513_172440`).
        echo "m260513_142613_DeduplicateElementTableForeignKeys cannot be reverted.\n";

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Enumerates every physical foreign key on `$table` and drops each by
     * name. Necessary because Yii's `TableSchema::foreignKeys` cache dedupes
     * by column-and-target-table; duplicate FKs are invisible to
     * `MigrationHelper::dropAllForeignKeysOnTable()`, which walks that
     * deduped collection and so drops only one of each pair.
     *
     * Reads `information_schema.table_constraints`, filtered to
     * `constraint_type = 'FOREIGN KEY'`. That view is ANSI, present and
     * identically shaped on both MySQL and PostgreSQL, and it carries one row
     * per physical constraint, which is exactly the property this migration
     * needs.
     *
     * It replaced `information_schema.referential_constraints`, which looked
     * equivalent and was not: `TABLE_NAME` there is a MySQL EXTENSION and does
     * not exist in the ANSI view, so on PostgreSQL the query referenced a
     * missing column and the migration threw. The uppercase identifiers were a
     * second, independent break, because PostgreSQL's catalog columns are
     * genuinely lowercase and Yii quotes what it is given. Between them they
     * made this migration a guaranteed abort on PostgreSQL, and made
     * {@see self::_informationSchemaScope()}'s carefully written PostgreSQL
     * branch unreachable. Everything here is lowercase for that reason: MySQL
     * treats INFORMATION_SCHEMA identifiers case-insensitively, PostgreSQL does
     * not.
     *
     * `$table` is the Yii-bracketed table name (e.g.
     * `{{%passwordpolicy_audit_log}}`). The prefix is resolved before the
     * lookup.
     *
     * @param string $table the bracketed table reference
     * @return void
     *
     * @throws \RuntimeException on an unsupported driver
     *
     * @author CraftPulse
     */
    private function _dropAllForeignKeysByName(string $table): void
    {
        $db = Craft::$app->getDb();
        $resolvedTable = $db->getSchema()->getRawTableName($table);

        $constraints = (new Query())
            ->select(['constraint_name'])
            ->from(['information_schema.table_constraints'])
            ->where([
                'table_schema' => $this->_informationSchemaScope(),
                'table_name' => $resolvedTable,
                'constraint_type' => 'FOREIGN KEY',
            ])
            ->column();

        foreach ($constraints as $name) {
            $this->dropForeignKey($name, $table);
        }
    }

    /**
     * Returns the value that scopes information_schema lookups to the
     * current connection.
     *
     * On MySQL, information_schema's `*_schema` columns hold the database
     * name (`DATABASE()`) — MySQL has no separate namespace concept. On
     * PostgreSQL, the same columns hold the namespace (`current_schema()`,
     * typically `public`); the database name lives in the `*_catalog`
     * columns instead. Scoping by the wrong value matches no rows and turns
     * the FK enumeration into a silent no-op.
     *
     * @return string the schema/database name to filter on
     *
     * @throws \RuntimeException on an unsupported driver
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _informationSchemaScope(): string
    {
        $db = Craft::$app->getDb();
        $driver = $db->getDriverName();

        if ($driver === Connection::DRIVER_MYSQL) {
            return (string)$db->createCommand('SELECT DATABASE()')->queryScalar();
        }

        if ($driver === Connection::DRIVER_PGSQL) {
            return (string)$db->createCommand('SELECT current_schema()')->queryScalar();
        }

        throw new \RuntimeException("Unsupported database driver for INFORMATION_SCHEMA enumeration: {$driver}.");
    }
}
