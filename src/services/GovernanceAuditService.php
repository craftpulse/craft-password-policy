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
use craftpulse\auditkit\audit\AuditEvent;
use craftpulse\auditkit\audit\AuditEventType;
use craftpulse\auditkit\AuditKit;
use craftpulse\passwordpolicy\models\PolicyModel;
use Throwable;
use yii\base\Component;

/**
 * Class GovernanceAuditService
 *
 * PP's emitter onto the shared Audit Kit dispatch bus. It publishes neutral
 * {@see AuditEvent}s for PP's own GOVERNANCE actions — named-policy saves and
 * deletes, and user-group → policy assignment changes — so a recorder on the bus
 * (Ledger, a compliance aggregator) captures PP's administrative changes through
 * the estate's one typed contract.
 *
 * One-seam discipline
 * -------------------
 * This is EMISSION only. PP does not register a recorder sink on the kit bus —
 * PP owns its own hash-chained `passwordpolicy_audit_log` and keeps its legacy
 * Auth Kit `AuthEvent` sink ({@see \craftpulse\passwordpolicy\integrations\AuthKitAuditSink}).
 * The bus emission here is ADDITIVE fan-out to external recorders; it never
 * replaces PP's own rows. PP's internal `policy_changed` chain row (fired from
 * {@see \craftpulse\passwordpolicy\elements\PolicyElement}) is untouched — the
 * governance bus events are a distinct, coarser signal aimed at the estate log.
 *
 * Fail-closed allowlist
 * ---------------------
 * Each governance event type is registered with the kit's runtime
 * {@see \craftpulse\auditkit\services\EventTypes} registry via {@see eventTypes()}
 * so a recorder strips any `details` key outside the declared scalar allowlist.
 * Every allowlisted key is a non-PII scalar — a policy handle/uid, a user-group
 * uid, an assignment verb. No email, no raw identifier, ever.
 *
 * Fail-soft
 * ---------
 * Every emitter method swallows its own throwables — a bus/registry problem must
 * never unwind a committed policy save or delete.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GovernanceAuditService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * The coarse grouping every governance event lands in. Policy + assignment
     * changes are access-control governance, so they group under `permissions`.
     *
     * @var string
     */
    public const CATEGORY = 'permissions';

    /**
     * The emitting plugin handle carried on every event.
     *
     * @var string
     */
    public const EMITTER = 'password-policy';

    /**
     * Machine-key for a user-group → policy assignment change. Fired once per
     * group added to or removed from a policy's assignment set.
     *
     * @var string
     */
    public const EVENT_GROUP_ASSIGNMENT_CHANGED = 'passwordpolicy.group_assignment_changed';

    /**
     * Machine-key for a named-policy delete.
     *
     * @var string
     */
    public const EVENT_POLICY_DELETED = 'passwordpolicy.policy_deleted';

    /**
     * Machine-key for a named-policy save (insert or update).
     *
     * @var string
     */
    public const EVENT_POLICY_SAVED = 'passwordpolicy.policy_saved';

    /**
     * The `targetType` carried on every governance event — the thing acted upon
     * is always a password policy.
     *
     * @var string
     */
    public const TARGET_TYPE = 'passwordPolicy';

    // Public Methods
    // =========================================================================

    /**
     * Returns the governance {@see AuditEventType} definitions PP contributes to
     * the shared Audit Kit registry. Each declares its category and the exact
     * scalar `details` allowlist a recorder may persist — the codified,
     * fail-closed privacy contract for PP's governance surface.
     *
     * @return AuditEventType[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function eventTypes(): array
    {
        return [
            new AuditEventType(
                name: self::EVENT_POLICY_SAVED,
                category: self::CATEGORY,
                label: Craft::t('password-policy', 'Password policy saved'),
                allowedDetailKeys: ['handle', 'uid', 'isNew'],
            ),
            new AuditEventType(
                name: self::EVENT_POLICY_DELETED,
                category: self::CATEGORY,
                label: Craft::t('password-policy', 'Password policy deleted'),
                allowedDetailKeys: ['handle', 'uid'],
            ),
            new AuditEventType(
                name: self::EVENT_GROUP_ASSIGNMENT_CHANGED,
                category: self::CATEGORY,
                label: Craft::t('password-policy', 'Policy group assignment changed'),
                allowedDetailKeys: ['policyHandle', 'policyUid', 'groupUid', 'change'],
            ),
        ];
    }

    /**
     * Emits one {@see AuditEvent} per user-group whose assignment to the policy
     * changed between the old and new assignment sets. Group order is not
     * semantic, so only genuine additions/removals fire — a reordered set emits
     * nothing. Each event carries the changed group's uid (never its id, never a
     * name) and the verb `assigned` / `unassigned`.
     *
     * @param PolicyModel $policy the saved policy
     * @param int[] $oldGroupIds the assignment set before the save
     * @param int[] $newGroupIds the assignment set after the save
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function groupsChanged(PolicyModel $policy, array $oldGroupIds, array $newGroupIds): void
    {
        $old = array_map('intval', $oldGroupIds);
        $new = array_map('intval', $newGroupIds);

        $assigned = array_diff($new, $old);
        $unassigned = array_diff($old, $new);

        foreach ($assigned as $groupId) {
            $this->_emitGroupAssignment($policy, $groupId, 'assigned');
        }

        foreach ($unassigned as $groupId) {
            $this->_emitGroupAssignment($policy, $groupId, 'unassigned');
        }
    }

    /**
     * Emits a `policy_deleted` governance event onto the bus.
     *
     * @param int $id the deleted policy's id
     * @param string|null $handle the deleted policy's handle
     * @param string|null $uid the deleted policy's uid
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function policyDeleted(int $id, ?string $handle, ?string $uid): void
    {
        $this->_record(new AuditEvent(
            name: self::EVENT_POLICY_DELETED,
            category: self::CATEGORY,
            emitter: self::EMITTER,
            outcome: AuditEvent::OUTCOME_SUCCESS,
            actorId: $this->_actorId(),
            targetType: self::TARGET_TYPE,
            targetId: $id,
            targetUid: $uid,
            details: [
                'handle' => $handle,
                'uid' => $uid,
            ],
        ));
    }

    /**
     * Emits a `policy_saved` governance event onto the bus.
     *
     * @param PolicyModel $policy the saved policy (id + uid populated)
     * @param bool $isNew whether the save was an insert
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function policySaved(PolicyModel $policy, bool $isNew): void
    {
        $this->_record(new AuditEvent(
            name: self::EVENT_POLICY_SAVED,
            category: self::CATEGORY,
            emitter: self::EMITTER,
            outcome: AuditEvent::OUTCOME_SUCCESS,
            actorId: $this->_actorId(),
            targetType: self::TARGET_TYPE,
            targetId: $policy->id,
            targetUid: $policy->uid,
            details: [
                'handle' => $policy->handle,
                'uid' => $policy->uid,
                'isNew' => $isNew,
            ],
        ));
    }

    // Private Methods
    // =========================================================================

    /**
     * Resolves the acting user's id, or null in a console request or when no
     * user is authenticated (a system-initiated save).
     *
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _actorId(): ?int
    {
        if (Craft::$app->getRequest()->getIsConsoleRequest()) {
            return null;
        }

        return Craft::$app->getUser()->getIdentity()?->id;
    }

    /**
     * Resolves a user-group's uid and emits a single `group_assignment_changed`
     * event for it. A group that can't be resolved (already deleted) is skipped
     * silently — there is no non-PII scalar to carry.
     *
     * @param PolicyModel $policy
     * @param int $groupId
     * @param string $change `assigned` or `unassigned`
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitGroupAssignment(PolicyModel $policy, int $groupId, string $change): void
    {
        $group = Craft::$app->getUserGroups()->getGroupById($groupId);

        if ($group === null) {
            return;
        }

        $this->_record(new AuditEvent(
            name: self::EVENT_GROUP_ASSIGNMENT_CHANGED,
            category: self::CATEGORY,
            emitter: self::EMITTER,
            outcome: AuditEvent::OUTCOME_SUCCESS,
            actorId: $this->_actorId(),
            targetType: self::TARGET_TYPE,
            targetId: $policy->id,
            targetUid: $policy->uid,
            details: [
                'policyHandle' => $policy->handle,
                'policyUid' => $policy->uid,
                'groupUid' => $group->uid,
                'change' => $change,
            ],
        ));
    }

    /**
     * Fans an event onto the shared Audit Kit bus, swallowing any throwable so a
     * bus/registry failure can never unwind the committed governance action that
     * triggered it. With no recorder sink registered, `record()` is a cheap
     * no-op.
     *
     * @param AuditEvent $event
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _record(AuditEvent $event): void
    {
        try {
            AuditKit::$plugin->getBus()->record($event);
        } catch (Throwable $e) {
            Craft::error(
                sprintf(
                    'Failed to emit governance audit event "%s": %s',
                    $event->name,
                    $e->getMessage(),
                ),
                'password-policy',
            );
        }
    }
}
