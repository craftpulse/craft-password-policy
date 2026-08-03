<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\db\Query;
use craftpulse\passwordpolicy\elements\PolicyElement;
use craftpulse\passwordpolicy\events\PolicySaveEvent;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\Component;

/**
 * Class PolicyService
 *
 * Manages CRUD operations for named password policies.
 *
 * Tri-layer storage pairing (Step 6 element-ification)
 * ----------------------------------------------------
 * As of 5.2.0 the service translates between the public-facing model
 * (`PolicyModel`) and the underlying element + record pair
 * (`PolicyElement` + `PolicyRecord`). The model stays the validation
 * surface + form-binding shape the CP controller and tests rely on;
 * the element is the persistence surface (queryable + indexable + the
 * G4 audit-diff carrier); the record is the storage layer. The service
 * is the bridge — `savePolicy(PolicyModel, array $groupIds)` continues
 * to accept the same payload third-party code has always passed in, but
 * routes the actual write through `Craft::$app->getElements()->saveElement()`
 * on a hydrated PolicyElement.
 *
 * Audit capture — moved to element lifecycle (G4 invariant preserved)
 * -------------------------------------------------------------------
 * Pre-Step-6, the pre-save state capture + diff fire lived inline in
 * `savePolicy()`. The element refactor moves that to
 * `PolicyElement::beforeSave()` (pre-save snapshot) +
 * `PolicyElement::afterSave()` (diff fire). The `policy_changed` event
 * payload + diff shape are bit-identical to before — `PolicyDiffCaptureTest`
 * pins the contract. The migration was about WHERE the diff fires, not
 * WHAT it fires.
 *
 * Maps to ISO 27002 A.5.37, SOC 2 CC8.1, and NIS2 Article 21(2)(e)
 * change-management evidence — auditors reading the audit log can
 * reconstruct who changed which policy field when.
 *
 * Extension seam (preserved across Step 6)
 * ----------------------------------------
 * `EVENT_BEFORE_SAVE_POLICY` and `EVENT_AFTER_SAVE_POLICY` are the
 * public extension surface for third-party listeners (external audit
 * mirroring, custom validation veto, CRM/SIEM sync). The event payload
 * remains `(PolicyModel $policy, array $groupIds, bool $isNew)` — the
 * service-level event surface is unchanged. BEFORE fires before
 * element construction so vetoers short-circuit cheaply (no element
 * pipeline overhead); AFTER fires after `saveElement()` returns,
 * matching the canonical "policy saved" moment listeners observed
 * before Step 6.
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
     * Fired by `savePolicy()` AFTER the policy validates but BEFORE any
     * DB I/O — element construction + persistence + the junction-table
     * sync all happen downstream of this event.
     *
     * Listeners may amend `$event->policy` (the amended model is what
     * gets persisted) or flip `$event->isValid = false` to abort the
     * save. When a listener vetoes, `savePolicy()` returns `false` and
     * no element row is written. The event matches the canonical Craft /
     * Yii idiom (`Element::EVENT_BEFORE_SAVE`) — `ModelEvent::$isValid`
     * defaults to `true` and the listener flips it to `false` to abort.
     *
     * Does NOT fire when `$policy->validate()` rejects the model — the
     * event surface is reserved for valid-shape policies. Listeners
     * that want to add validation rules should listen on
     * `Model::EVENT_AFTER_VALIDATE` on `PolicyModel` directly, not on
     * this seam.
     *
     * @event PolicySaveEvent
     *
     * @since 5.2.0
     */
    public const EVENT_BEFORE_SAVE_POLICY = 'beforeSavePolicy';

    /**
     * Fired by `savePolicy()` AFTER `Craft::$app->getElements()->saveElement()`
     * successfully returns. Listeners observe the canonical "policy
     * saved" moment — the element row is on disk, the paired
     * `PolicyRecord` is upserted, the junction-table sync is done,
     * `$event->policy->id` is populated (even on the INSERT path,
     * where it was null when `EVENT_BEFORE_SAVE_POLICY` fired), and
     * the G4 `policy_changed` audit row (if applicable) has been
     * fired from the element's `afterSave()`.
     *
     * Does NOT fire on:
     *   - validation failure (`$policy->validate()` returned false),
     *   - veto on `EVENT_BEFORE_SAVE_POLICY` (listener set `isValid = false`),
     *   - element-save failure (`saveElement()` returned false).
     *
     * Branch on `$event->isNew` to distinguish "newly created" from
     * "updated existing" — the flag reflects the pre-save shape and
     * stays stable across before/after.
     *
     * The `$isValid` flag is inherited from `ModelEvent` but
     * meaningless here — the save is already committed, listeners
     * cannot abort it.
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
        $elements = PolicyElement::find()
            ->orderBy(['passwordpolicy_policies.sortOrder' => SORT_ASC])
            ->all();

        return array_map(static fn(PolicyElement $element) => PolicyModel::fromElement($element), $elements);
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
        $element = PolicyElement::find()->id($id)->one();

        return $element instanceof PolicyElement ? PolicyModel::fromElement($element) : null;
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
        $element = PolicyElement::find()->handle($handle)->one();

        return $element instanceof PolicyElement ? PolicyModel::fromElement($element) : null;
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

        $elements = PolicyElement::find()
            ->groupId($groupIds)
            ->orderBy(['passwordpolicy_policies.sortOrder' => SORT_ASC])
            ->all();

        return array_map(static fn(PolicyElement $element) => PolicyModel::fromElement($element), $elements);
    }

    /**
     * Saves a policy and syncs its group assignments.
     *
     * Translation flow:
     *
     *  1. Validate the in-memory `PolicyModel` (cheap, no DB I/O).
     *  2. Fire `EVENT_BEFORE_SAVE_POLICY` — listeners may amend or veto.
     *  3. Build a `PolicyElement` from the model + groupIds and route
     *     through `Craft::$app->getElements()->saveElement()`.
     *  4. Element pipeline runs `beforeSave()` (snapshot capture),
     *     inserts the `craft_elements` row, upserts the paired
     *     `PolicyRecord`, syncs the junction, and fires the G4
     *     `policy_changed` audit event from `afterSave()`.
     *  5. Pull the persisted id back onto the model so callers see a
     *     populated id (matters for INSERTs).
     *  6. Fire `EVENT_AFTER_SAVE_POLICY`.
     *
     * @param PolicyModel $policy the policy to save
     * @param int[] $groupIds the group IDs to assign
     * @return bool whether the save was successful
     *
     * @throws Throwable
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
        // or flip `$event->isValid = false` to abort the save before
        // any element pipeline I/O occurs. Vetoers short-circuit
        // cheaply; the element + record + junction writes downstream
        // run only when the event survives.
        $beforeEvent = new PolicySaveEvent([
            'policy' => $policy,
            'groupIds' => $groupIds,
            'isNew' => $policy->id === null,
        ]);
        $this->trigger(self::EVENT_BEFORE_SAVE_POLICY, $beforeEvent);

        if (!$beforeEvent->isValid) {
            return false;
        }

        // Track the pre-save shape — `saveElement()` will populate
        // `policy->id` on the INSERT branch via the element pipeline's
        // id-pullback below, so capture isNew before the round-trip.
        $isNew = $policy->id === null;

        // Snapshot the on-disk group assignments before the save so the
        // governance bus emission below can diff old vs new and fire one
        // `group_assignment_changed` event per genuine add/remove. A new
        // policy has no prior assignments.
        $oldGroupIds = $isNew ? [] : $this->_assignedGroupIds($policy->id);

        $element = PolicyElement::fromModel($policy, $groupIds);

        if (!Craft::$app->getElements()->saveElement($element)) {
            // Propagate element-level errors back onto the model so
            // the caller sees attribute-keyed validation messages.
            foreach ($element->getErrors() as $attribute => $errors) {
                foreach ($errors as $message) {
                    $policy->addError($attribute, $message);
                }
            }
            return false;
        }

        // Pull the persisted id back onto the model so INSERT callers
        // see the populated id on return. The element pipeline
        // generates the id from `craft_elements`; the paired record
        // and the model share it.
        $policy->id = (int)$element->id;
        $policy->uid = $element->uid;

        // External extension seam — fires AFTER `saveElement()`
        // returns. Listeners observe the canonical "policy saved"
        // moment: element + record + junction are all on disk, and
        // the G4 `policy_changed` audit event (if applicable) was
        // already fired by the element's `afterSave()`.
        $afterEvent = new PolicySaveEvent([
            'policy' => $policy,
            'groupIds' => $groupIds,
            'isNew' => $isNew,
        ]);
        $this->trigger(self::EVENT_AFTER_SAVE_POLICY, $afterEvent);

        // Governance fan-out onto the shared Audit Kit bus — ADDITIVE to PP's
        // own `policy_changed` chain row (fired from the element's afterSave()),
        // never a replacement. Emits `policy_saved` once and one
        // `group_assignment_changed` per genuine assignment add/remove. The
        // emitter is fail-soft; a bus problem can't unwind the committed save.
        $governance = PasswordPolicy::$plugin->getGovernanceAudit();
        $governance->policySaved($policy, $isNew);
        $governance->groupsChanged($policy, $oldGroupIds, $groupIds);

        return true;
    }

    /**
     * Hard-deletes a policy by ID. Junction rows are removed by the
     * `passwordpolicy_policy_groups.policyId → policies.id` CASCADE
     * after the `craft_elements` row is dropped.
     *
     * Routes through `Elements::deleteElementById()` with
     * `hardDelete: true` to preserve the pre-Step-6 UX (permanent
     * delete from the CP index). The element layer's soft-delete path
     * is reachable from the native element index (Delete action), but
     * the legacy service-level API stays hard-delete to avoid
     * breaking callers that expect rows to actually disappear.
     *
     * @param int $id the policy ID
     * @return bool whether the delete was successful
     *
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function deletePolicy(int $id): bool
    {
        // Resolve the handle + uid BEFORE the delete so the governance emission
        // below carries them (post-delete the row is gone). A missing policy
        // yields nulls, and the delete still runs to preserve prior behaviour.
        $policy = $this->getPolicyById($id);
        $handle = $policy?->handle;
        $uid = $policy?->uid;

        $deleted = (bool)Craft::$app->getElements()->deleteElementById($id, PolicyElement::class, hardDelete: true);

        if ($deleted) {
            // Governance fan-out onto the shared Audit Kit bus (fail-soft).
            PasswordPolicy::$plugin->getGovernanceAudit()->policyDeleted($id, $handle, $uid);
        }

        return $deleted;
    }

    /**
     * Reorders policies by updating sortOrder for each ID in the array.
     *
     * Direct UPDATE rather than round-tripping each row through the
     * element pipeline — reorder is a bulk sortOrder write, not a
     * semantic policy edit. Skipping the pipeline avoids firing
     * `policy_changed` audit events for every drag-and-drop reorder
     * (which would noise the audit log without operational value).
     *
     * @param int[] $ids the ordered policy IDs
     * @return bool whether the reorder was successful
     *
     * @throws Throwable
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
        } catch (Throwable $e) {
            $transaction->rollBack();
            throw $e;
        }

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the user-group ids currently assigned to a policy, read straight
     * from the junction table. Used to diff group assignments for the
     * governance bus emission without round-tripping the element pipeline.
     *
     * @param int $policyId
     * @return int[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _assignedGroupIds(int $policyId): array
    {
        $groupIds = (new Query())
            ->select(['groupId'])
            ->from('{{%passwordpolicy_policy_groups}}')
            ->where(['policyId' => $policyId])
            ->column();

        return array_map('intval', $groupIds);
    }
}
