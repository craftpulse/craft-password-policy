<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\db\Query;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\PolicyModel;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class PolicyService
 *
 * Manages CRUD operations for named password policies.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Returns all named policies ordered by sortOrder.
     *
     * @return PolicyModel[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAllPolicies(): array
    {
        $rows = (new Query())
            ->select('*')
            ->from('{{%passwordpolicy_policies}}')
            ->orderBy(['sortOrder' => SORT_ASC])
            ->all();

        return array_map(fn(array $row) => $this->_hydratePolicy($row), $rows);
    }

    /**
     * Returns a policy by its ID.
     *
     * @param int $id the policy ID
     * @return PolicyModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPolicyById(int $id): ?PolicyModel
    {
        $row = (new Query())
            ->select('*')
            ->from('{{%passwordpolicy_policies}}')
            ->where(['id' => $id])
            ->one();

        if (!$row) {
            return null;
        }

        return $this->_hydratePolicy($row);
    }

    /**
     * Returns a policy by its handle.
     *
     * @param string $handle the policy handle
     * @return PolicyModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPolicyByHandle(string $handle): ?PolicyModel
    {
        $row = (new Query())
            ->select('*')
            ->from('{{%passwordpolicy_policies}}')
            ->where(['handle' => $handle])
            ->one();

        if (!$row) {
            return null;
        }

        return $this->_hydratePolicy($row);
    }

    /**
     * Returns all policies assigned to any of the given group IDs.
     *
     * Joins through the junction table and deduplicates by grouping.
     *
     * @param int[] $groupIds the user group IDs to match
     * @return PolicyModel[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPoliciesForGroupIds(array $groupIds): array
    {
        if (empty($groupIds)) {
            return [];
        }

        $rows = (new Query())
            ->select('p.*')
            ->from(['p' => '{{%passwordpolicy_policies}}'])
            ->innerJoin(
                ['pg' => '{{%passwordpolicy_policy_groups}}'],
                '[[pg.policyId]] = [[p.id]]',
            )
            ->where(['pg.groupId' => $groupIds])
            ->groupBy('p.id')
            ->orderBy(['p.sortOrder' => SORT_ASC])
            ->all();

        return array_map(fn(array $row) => $this->_hydratePolicy($row), $rows);
    }

    /**
     * Saves a policy and syncs its group assignments.
     *
     * @param PolicyModel $policy the policy to save
     * @param int[] $groupIds the group IDs to assign
     * @return bool whether the save was successful
     *
     * @throws \Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function savePolicy(PolicyModel $policy, array $groupIds = []): bool
    {
        if (!$policy->validate()) {
            return false;
        }

        $db = Craft::$app->getDb();
        $transaction = $db->beginTransaction();

        try {
            $now = (new \DateTime())->format('Y-m-d H:i:s');
            $settingsJson = Json::encode($policy->getSettingsArray());

            $attrs = [
                'name' => $policy->name,
                'handle' => $policy->handle,
                'preset' => $policy->preset,
                'settings' => $settingsJson,
                'sortOrder' => $policy->sortOrder,
                'dateUpdated' => $now,
            ];

            if ($policy->id !== null) {
                // Update existing
                $db->createCommand()
                    ->update('{{%passwordpolicy_policies}}', $attrs, ['id' => $policy->id])
                    ->execute();
            } else {
                // Insert new
                $attrs['dateCreated'] = $now;
                $attrs['uid'] = $policy->uid ?? StringHelper::UUID();

                $db->createCommand()
                    ->insert('{{%passwordpolicy_policies}}', $attrs)
                    ->execute();

                $policy->id = (int)$db->getLastInsertID('{{%passwordpolicy_policies}}');
            }

            // Sync junction table
            $db->createCommand()
                ->delete('{{%passwordpolicy_policy_groups}}', ['policyId' => $policy->id])
                ->execute();

            foreach ($groupIds as $groupId) {
                $db->createCommand()
                    ->insert('{{%passwordpolicy_policy_groups}}', [
                        'policyId' => $policy->id,
                        'groupId' => (int)$groupId,
                        'dateCreated' => $now,
                        'dateUpdated' => $now,
                        'uid' => StringHelper::UUID(),
                    ])
                    ->execute();
            }

            $transaction->commit();
        } catch (\Throwable $e) {
            $transaction->rollBack();
            throw $e;
        }

        return true;
    }

    /**
     * Deletes a policy by ID. Junction rows are removed by CASCADE.
     *
     * @param int $id the policy ID
     * @return bool whether the delete was successful
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function deletePolicy(int $id): bool
    {
        $affectedRows = Craft::$app->getDb()->createCommand()
            ->delete('{{%passwordpolicy_policies}}', ['id' => $id])
            ->execute();

        return $affectedRows > 0;
    }

    /**
     * Reorders policies by updating sortOrder for each ID in the array.
     *
     * @param int[] $ids the ordered policy IDs
     * @return bool whether the reorder was successful
     *
     * @throws \Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function reorderPolicies(array $ids): bool
    {
        $db = Craft::$app->getDb();
        $transaction = $db->beginTransaction();

        try {
            foreach ($ids as $sortOrder => $id) {
                $db->createCommand()
                    ->update(
                        '{{%passwordpolicy_policies}}',
                        ['sortOrder' => $sortOrder],
                        ['id' => $id],
                    )
                    ->execute();
            }

            $transaction->commit();
        } catch (\Throwable $e) {
            $transaction->rollBack();
            throw $e;
        }

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Hydrates a PolicyModel from a database row.
     *
     * @param array $row the database row
     * @return PolicyModel
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hydratePolicy(array $row): PolicyModel
    {
        $model = new PolicyModel();
        $model->id = (int)$row['id'];
        $model->name = $row['name'];
        $model->handle = $row['handle'];
        $model->preset = $row['preset'] ?? null;
        $model->sortOrder = (int)$row['sortOrder'];
        $model->uid = $row['uid'] ?? null;

        // Decode JSON settings column — handles double-encoded values
        // from migration (json_encode + Yii2 JSON column type)
        $settings = $row['settings'] ?? null;

        if (is_string($settings)) {
            $decoded = Json::decodeIfJson($settings);

            // Double-encoded: first decode yields string, second yields array
            if (is_string($decoded)) {
                $decoded = Json::decodeIfJson($decoded);
            }

            if (is_array($decoded)) {
                $model->setSettingsFromArray($decoded);
            }
        }

        return $model;
    }
}
