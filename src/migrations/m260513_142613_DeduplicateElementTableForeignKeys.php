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
 * Why this migration uses raw INFORMATION_SCHEMA enumeration instead
 * of `MigrationHelper::dropAllForeignKeysOnTable()`: Yii's
 * `TableSchema::foreignKeys` array dedupes by column-and-referenced-
 * table, so when two FK constraints reference the same column on the
 * same target table, the schema cache only exposes one of them.
 * `dropAllForeignKeysOnTable` walks that deduped collection and only
 * drops one of each pair. The raw INFORMATION_SCHEMA query sees every
 * physical constraint independently and lets us drop them all
 * unambiguously.
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

        $this->_dropAllForeignKeysByName($auditLog);
        $this->_dropAllForeignKeysByName($notificationLog);

        // audit_log: id → elements (CASCADE), userId + changedByUserId → users (SET NULL).
        $this->addForeignKey(null, $auditLog, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $auditLog, ['userId'], Table::USERS, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $auditLog, ['changedByUserId'], Table::USERS, ['id'], 'SET NULL', null);

        // notification_log: id → elements (CASCADE), userId → users (SET NULL),
        // siteId → sites (SET NULL), resentFromId → self (SET NULL).
        $this->addForeignKey(null, $notificationLog, ['id'], Table::ELEMENTS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $notificationLog, ['userId'], Table::USERS, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $notificationLog, ['siteId'], Table::SITES, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, $notificationLog, ['resentFromId'], $notificationLog, ['id'], 'SET NULL', null);

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeDown(): bool
    {
        // Cannot meaningfully revert — restoring the duplicate state
        // would re-create the constraint mess the up migration cleaned
        // up. Down-migration is a no-op success.
        return true;
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
     * `{{%passwordpolicy_audit_log}}`). The prefix is resolved before
     * the INFORMATION_SCHEMA lookup.
     *
     * @param string $table the bracketed table reference
     * @return void
     *
     * @author CraftPulse
     */
    private function _dropAllForeignKeysByName(string $table): void
    {
        $db = Craft::$app->getDb();
        $resolvedTable = $db->getSchema()->getRawTableName($table);

        // `Schema::defaultSchema` is empty string for MySQL — it tracks
        // a PostgreSQL concept that doesn't exist in MySQL where
        // "schemas" are "databases". Use `SELECT DATABASE()` to get
        // the current database name so the INFORMATION_SCHEMA lookup
        // scopes correctly. Without this, the query matches no rows
        // and the drop loop becomes a silent no-op.
        $currentDatabase = $db->createCommand('SELECT DATABASE()')->queryScalar();

        $constraints = (new Query())
            ->select('CONSTRAINT_NAME')
            ->from('INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS')
            ->where([
                'CONSTRAINT_SCHEMA' => $currentDatabase,
                'TABLE_NAME' => $resolvedTable,
            ])
            ->column();

        foreach ($constraints as $name) {
            $this->dropForeignKey($name, $table);
        }
    }
}
