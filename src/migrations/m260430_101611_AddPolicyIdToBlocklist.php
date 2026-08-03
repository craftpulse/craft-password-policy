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
 * m260430_101611_AddPolicyIdToBlocklist migration.
 *
 * Adds nullable `policyId` column to `passwordpolicy_blocklist` so individual
 * blocklist entries can be scoped to a specific named policy. NULL = global
 * (applies to every policy that enables `checkCommonPasswords`); set = entry
 * only matters when that policy is in the resolved set for the user. The
 * column is reserved for the Enterprise per-policy custom dictionary editor;
 * Pro saves global entries (`policyId IS NULL`) only.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260430_101611_AddPolicyIdToBlocklist extends Migration
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
        $table = '{{%passwordpolicy_blocklist}}';

        if (!$this->db->columnExists($table, 'policyId')) {
            $this->addColumn($table, 'policyId', $this->integer()->null()->after('source'));
            $this->createIndex(null, $table, ['policyId'], false);
            $this->addForeignKey(
                null,
                $table,
                ['policyId'],
                '{{%passwordpolicy_policies}}',
                ['id'],
                'CASCADE',
                null,
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
        echo "m260430_101611_AddPolicyIdToBlocklist cannot be reverted.\n";
        return false;
    }
}
