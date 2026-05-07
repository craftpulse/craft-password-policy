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
use craftpulse\passwordpolicy\events\PolicySaveEvent;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class PolicyService
 *
 * Manages CRUD operations for named password policies.
 *
 * Audit capture (Phase G — G4)
 * ----------------------------
 * On a successful UPDATE, `savePolicy()` fires the `policy_changed`
 * audit event with a structured `{field: {old, new}}` diff covering
 * top-level columns (`name`, `handle`, `preset`, `sortOrder`), every
 * settings-array key the model exposes, and group assignments
 * (`groupIds`). Unchanged fields are omitted; INSERT-path saves do
 * not fire (a future `policy_created` event is out of scope for G4).
 *
 * Capture is inline rather than event-driven on purpose: G4 needs the
 * pre-save state captured before the transaction, and an after-save
 * listener would have to either re-query (wasteful) or rely on the
 * event payload carrying pre-state (couples the event to one consumer's
 * needs). The inline path serves G4 cleanly. The audit `logEvent()`
 * call is wrapped in try/catch because the parent transaction is
 * already committed — an audit failure must never unwind a saved policy.
 *
 * Maps to ISO 27002 A.5.37, SOC 2 CC8.1, and NIS2 Article 21(2)(e)
 * change-management evidence — auditors reading the audit log can
 * reconstruct who changed which policy field when.
 *
 * Extension seam
 * --------------
 * `EVENT_BEFORE_SAVE_POLICY` and `EVENT_AFTER_SAVE_POLICY` are the
 * public extension surface for third-party listeners (external audit
 * mirroring, custom validation veto, CRM/SIEM sync). They run parallel
 * to the inline G4 capture above — BEFORE fires before any DB I/O so
 * vetoers short-circuit cheaply; AFTER fires after `commit()` and
 * before the inline G4 audit-diff so external listeners observe the
 * save before the audit row is written. See `events/PolicySaveEvent.php`
 * for the veto contract and `$isNew` semantics.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Fired by `savePolicy()` AFTER the policy validates but BEFORE any DB
     * I/O — pre-save state capture, the transaction, and the junction-table
     * sync all happen downstream of this event.
     *
     * Listeners may amend `$event->policy` (the amended model is what gets
     * persisted) or flip `$event->isValid = false` to abort the save. When
     * a listener vetoes, `savePolicy()` returns `false` and no row is
     * written. The event matches the canonical Craft / Yii idiom
     * (`Element::EVENT_BEFORE_SAVE`) — `ModelEvent::$isValid` defaults to
     * `true` and the listener flips it to `false` to abort.
     *
     * Does NOT fire when `$policy->validate()` rejects the model — the
     * event surface is reserved for valid-shape policies. Listeners that
     * want to add validation rules should listen on `Model::EVENT_AFTER_VALIDATE`
     * on `PolicyModel` directly, not on this seam.
     *
     * @event PolicySaveEvent
     *
     * @since 5.2.0
     */
    public const EVENT_BEFORE_SAVE_POLICY = 'beforeSavePolicy';

    /**
     * Fired by `savePolicy()` AFTER the transaction successfully commits.
     * Listeners observe the canonical "policy saved" moment — the row is
     * on disk, the junction-table sync is done, and `$event->policy->id`
     * is populated (even on the INSERT path, where it was null when
     * `EVENT_BEFORE_SAVE_POLICY` fired).
     *
     * Does NOT fire on:
     *   - validation failure (`$policy->validate()` returned false),
     *   - veto on `EVENT_BEFORE_SAVE_POLICY` (listener set `isValid = false`),
     *   - transaction rollback (a `\Throwable` thrown inside the write path).
     *
     * Branch on `$event->isNew` to distinguish "newly created" from
     * "updated existing" — the flag reflects the pre-save shape and stays
     * stable across before/after.
     *
     * Fires BEFORE the inline `policy_changed` audit-diff capture (G4),
     * so external listeners observe the save before the audit row is
     * written. An audit-write hiccup downstream cannot starve a registered
     * external listener.
     *
     * The `$isValid` flag is inherited from `ModelEvent` but meaningless
     * here — the save is already committed, listeners cannot abort it.
     *
     * @event PolicySaveEvent
     *
     * @since 5.2.0
     */
    public const EVENT_AFTER_SAVE_POLICY = 'afterSavePolicy';

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

        // External extension seam — listeners may amend `$event->policy`
        // or flip `$event->isValid = false` to abort the save before any
        // DB I/O occurs. Vetoers short-circuit cheaply; the
        // pre-save-state capture below runs only when the event survives.
        $beforeEvent = new PolicySaveEvent([
            'policy' => $policy,
            'groupIds' => $groupIds,
            'isNew' => $policy->id === null,
        ]);
        $this->trigger(self::EVENT_BEFORE_SAVE_POLICY, $beforeEvent);

        if (!$beforeEvent->isValid) {
            return false;
        }

        // Capture pre-save state for the `policy_changed` audit diff.
        // Only meaningful on the UPDATE branch; INSERTs have nothing to
        // diff against. Resolve before the transaction so the audit
        // payload reflects the on-disk row as it existed coming in.
        $isUpdate = $policy->id !== null;
        $existing = $isUpdate ? $this->getPolicyById((int)$policy->id) : null;
        $existingGroupIds = $isUpdate ? $this->_loadGroupIdsForPolicy((int)$policy->id) : [];

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

        // External extension seam — fires AFTER the commit (so listeners
        // observe the canonical "policy saved" moment) and BEFORE the
        // inline G4 audit-diff capture (so an audit-write hiccup downstream
        // cannot starve a registered external listener). `$isUpdate` was
        // captured before the INSERT branch flipped `$policy->id`, so
        // `isNew` correctly reflects the pre-save shape.
        $afterEvent = new PolicySaveEvent([
            'policy' => $policy,
            'groupIds' => $groupIds,
            'isNew' => !$isUpdate,
        ]);
        $this->trigger(self::EVENT_AFTER_SAVE_POLICY, $afterEvent);

        // Audit diff fires AFTER commit — never unwind a saved policy
        // because of a downstream audit-write hiccup. INSERTs are out
        // of scope for G4 (no `policy_created` event class).
        if ($isUpdate && $existing !== null) {
            $diff = $this->_buildPolicyDiff(
                existing: $existing,
                existingGroupIds: $existingGroupIds,
                updated: $policy,
                updatedGroupIds: array_map(static fn($id): int => (int)$id, $groupIds),
            );

            if (!empty($diff)) {
                $this->_logPolicyChanged($policy, $diff);
            }
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
     * Builds the field-level `{field: {old, new}}` diff for the
     * `policy_changed` audit event.
     *
     * Compared surfaces:
     *
     *  - Top-level columns: `name`, `handle`, `preset`, `sortOrder`.
     *  - Every key in `PolicyModel::settingsFields()` — sourced from
     *    the model's `getSettingsArray()` so null (inherit) values
     *    are normalised on both sides of the comparison.
     *  - `groupIds` — the assigned-groups junction. Sorted (numeric
     *    ascending) before comparison; group order is not semantic.
     *    When changed, emits the FULL old + new arrays so the auditor
     *    sees the assignment as a unit, not a sequence of add/remove
     *    deltas.
     *
     * Boolean tri-state settings (`?bool`) emit `null` / `true` /
     * `false` literally — no coercion. JSON canonicalisation in the
     * audit row preserves these as the auditor needs them.
     *
     * Unchanged fields are omitted entirely; an empty diff means the
     * caller should skip the audit write (no-op save).
     *
     * @param PolicyModel $existing the on-disk policy as it was before save
     * @param int[] $existingGroupIds the on-disk junction-row group IDs
     * @param PolicyModel $updated the in-memory policy that just landed
     * @param int[] $updatedGroupIds the group IDs the caller passed in
     * @return array<string, array{old: mixed, new: mixed}>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildPolicyDiff(
        PolicyModel $existing,
        array $existingGroupIds,
        PolicyModel $updated,
        array $updatedGroupIds,
    ): array {
        $diff = [];

        // Top-level columns. `sortOrder` is cast to int on both sides
        // because the in-memory model can carry a string sortOrder
        // pulled from a form submission while the hydrated record is
        // already int-cast.
        $topLevel = [
            'name' => [$existing->name, $updated->name],
            'handle' => [$existing->handle, $updated->handle],
            'preset' => [$existing->preset, $updated->preset],
            'sortOrder' => [(int)$existing->sortOrder, (int)$updated->sortOrder],
        ];

        foreach ($topLevel as $field => [$old, $new]) {
            if ($old !== $new) {
                $diff[$field] = ['old' => $old, 'new' => $new];
            }
        }

        // Settings array — every field in `PolicyModel::settingsFields()`.
        // Use `getSettingsArray()` to normalise null (inherit) values:
        // `getSettingsArray()` omits nulls, so we walk the canonical
        // settingsFields() list and pull each value via property access
        // to capture explicit nulls in the diff.
        foreach (PolicyModel::settingsFields() as $field) {
            $oldValue = $existing->{$field};
            $newValue = $updated->{$field};

            if ($oldValue !== $newValue) {
                $diff[$field] = ['old' => $oldValue, 'new' => $newValue];
            }
        }

        // Group assignments. Sort both ascending — group order is not
        // semantic, swapping rows around in the junction table should
        // not produce a diff.
        $oldGroupIds = array_map(static fn($id): int => (int)$id, $existingGroupIds);
        $newGroupIds = array_map(static fn($id): int => (int)$id, $updatedGroupIds);
        sort($oldGroupIds, SORT_NUMERIC);
        sort($newGroupIds, SORT_NUMERIC);

        if ($oldGroupIds !== $newGroupIds) {
            $diff['groupIds'] = ['old' => $oldGroupIds, 'new' => $newGroupIds];
        }

        return $diff;
    }

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

    /**
     * Returns the user-group IDs currently assigned to the given policy
     * via the `passwordpolicy_policy_groups` junction table.
     *
     * Inlined into the audit diff path rather than reusing
     * `PolicyModel::getGroupIds()` so we don't accidentally hit the
     * model's `_groups` cache during the in-flight save.
     *
     * @param int $policyId the policy ID
     * @return int[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _loadGroupIdsForPolicy(int $policyId): array
    {
        return array_map(
            static fn($id): int => (int)$id,
            (new Query())
                ->select(['groupId'])
                ->from('{{%passwordpolicy_policy_groups}}')
                ->where(['policyId' => $policyId])
                ->column(),
        );
    }

    /**
     * Fires the `policy_changed` audit event for a successful UPDATE.
     *
     * Wrapped in try/catch — the parent `savePolicy()` transaction is
     * already committed at this point, and an audit-write failure must
     * never unwind a saved policy. AuditLogService internally fail-safes
     * its own writes, but the wrapping catch is belt-and-braces against
     * any future change to that contract.
     *
     * `userId` is null because the event subject is the policy itself,
     * not a user. The audit row's `changedByUserId` is auto-resolved
     * from the current admin context inside `AuditLogService::logEvent()`.
     *
     * @param PolicyModel $policy the policy that was just saved
     * @param array<string, array{old: mixed, new: mixed}> $diff the field-level diff
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _logPolicyChanged(PolicyModel $policy, array $diff): void
    {
        try {
            PasswordPolicy::$plugin->getAuditLog()->logEvent(
                userId: null,
                event: 'policy_changed',
                details: [
                    'diff' => $diff,
                    'policyId' => (int)$policy->id,
                    'policyName' => $policy->name,
                ],
            );
        } catch (Throwable $e) {
            Craft::error(
                'Failed to write policy_changed audit event: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }
}
