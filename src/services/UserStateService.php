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

use Carbon\Carbon;
use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\models\AuditContext;
use craftpulse\passwordpolicy\records\UserStateRecord;
use yii\base\Component;

/**
 * Class UserStateService
 *
 * Read/write surface over `passwordpolicy_user_state` — pending-reset
 * reasons + breach detection state per user. One sparsely-populated row
 * per user. Capture is non-negotiable across editions; gates apply to UI
 * / API / SIEM exposure of the state, not to the writes (memory rule
 * `project_audit_capture_principle.md`).
 *
 * Phase D0 ships the surface; D1 wires HIBP-on-login (calls
 * {@see self::recordBreachCheck()}) and the admin-action listeners
 * (call {@see self::setPendingReason()}). D2/D3 read state from the same
 * surface for user-index condition rules + element actions.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserStateService extends Component
{
    // Private Properties
    // =========================================================================

    /**
     * In-process explicit-context override slots, keyed by user id.
     *
     * D3's `ChangeUserPassword` element action sets a slot before invoking
     * `Elements::saveElement()` so the central history-write listener
     * (`PasswordPolicy::_resolveAuditContext()`) picks up the explicit
     * `AuditContext::adminChange()` instead of falling back to the
     * pending-reason or self-service paths. The slot is consumed exactly
     * once via {@see self::consumeExplicitContext()}; the listener clears
     * the slot so a follow-up save in the same request doesn't reuse a
     * stale context.
     *
     * Process-private (not persisted) — every web/console request boots
     * with an empty array. The slot only exists during the synchronous
     * window between `setExplicitContext()` and `saveElement()`'s
     * `EVENT_AFTER_SAVE` firing.
     *
     * @var array<int, AuditContext>
     */
    private static array $_explicitContexts = [];

    // Public Methods
    // =========================================================================

    /**
     * Returns the state row for a user, or null if no row exists yet.
     * Sparsely populated — most users will have no row until something
     * (HIBP-on-login detection, admin force-reset, etc.) writes one.
     *
     * @param User $user
     * @return UserStateRecord|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStateForUser(User $user): ?UserStateRecord
    {
        if ($user->id === null) {
            return null;
        }

        return UserStateRecord::findOne(['userId' => $user->id]);
    }

    /**
     * Sets a pending-reset reason on the user's state row, creating the
     * row if it doesn't exist yet. Idempotent — calling repeatedly with
     * the same reason updates `pendingResetSetAt` to the current time
     * and leaves the rest unchanged.
     *
     * @param User $user
     * @param ChangeReason $reason
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function setPendingReason(User $user, ChangeReason $reason): void
    {
        if ($user->id === null) {
            return;
        }

        $record = $this->_getOrCreateRecord($user->id);
        $record->pendingResetReason = $reason->value;
        $record->pendingResetSetAt = Carbon::now('UTC');
        $record->save(false);
    }

    /**
     * Clears any pending-reset reason on the user's state row. No-op if
     * no row exists. Called when an admin completes a forced reset, or
     * when the user themselves changes their password through the
     * normal flow.
     *
     * @param User $user
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function clearPendingReason(User $user): void
    {
        if ($user->id === null) {
            return;
        }

        $record = UserStateRecord::findOne(['userId' => $user->id]);

        if ($record === null) {
            return;
        }

        $record->pendingResetReason = null;
        $record->pendingResetSetAt = null;
        $record->save(false);
    }

    /**
     * Records a HIBP-on-login (or other) breach check against the user's
     * state row. Always updates `lastBreachCheckAt`; only updates
     * `lastBreachDetectedAt` when `$detected = true`.
     *
     * Privacy contract — never accepts plaintext, hashes, or HIBP bucket
     * suffixes. The `bool $detected` flag is the only signal worth
     * persisting (memory rule security.md). Don't extend this method to
     * accept a hash prefix — the audit trail isn't the place to retain
     * any HIBP-correlatable identifier beyond "we checked, here's the
     * outcome."
     *
     * @param User $user
     * @param bool $detected whether the check returned a breach
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recordBreachCheck(User $user, bool $detected): void
    {
        if ($user->id === null) {
            return;
        }

        $record = $this->_getOrCreateRecord($user->id);
        $now = Carbon::now('UTC');

        $record->lastBreachCheckAt = $now;

        if ($detected) {
            $record->lastBreachDetectedAt = $now;
        }

        $record->save(false);
    }

    /**
     * Pins an explicit `AuditContext` for the user's NEXT password-save
     * cycle. The central `EVENT_AFTER_SAVE` listener consumes the slot
     * via {@see self::consumeExplicitContext()} before falling back to
     * the pending-reason or self-service paths.
     *
     * D3 wires this from the `ChangeUserPassword` element action's
     * controller — admin direct intent must override any prior pending
     * reason (breach, expiry, etc.) on the user. Calling this BEFORE
     * `Craft::$app->getElements()->saveElement($user)` is the contract;
     * the listener clears the slot regardless of save outcome so a
     * stale context can't bleed into a later save.
     *
     * @param User $user the user being saved
     * @param AuditContext $context the explicit context to record
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function setExplicitContext(User $user, AuditContext $context): void
    {
        if ($user->id === null) {
            return;
        }

        self::$_explicitContexts[$user->id] = $context;
    }

    /**
     * Returns and clears any explicit `AuditContext` previously set for
     * the user via {@see self::setExplicitContext()}. Returns `null`
     * when no slot was set. Single-use — calling twice in a row returns
     * the context, then `null`.
     *
     * Called from the central history-write listener BEFORE the
     * pending-reason consume so explicit admin intent wins over any
     * prior `BreachForced` / `ExpiryForced` / `AdminForceReset` pending
     * reason on the user_state row. The listener separately calls
     * {@see self::clearPendingReason()} to drop the now-superseded
     * pending reason after the change lands.
     *
     * @param User $user the user whose explicit context should be consumed
     * @return AuditContext|null the explicit context if one was set, or
     *     `null` if no slot was reserved
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function consumeExplicitContext(User $user): ?AuditContext
    {
        if ($user->id === null) {
            return null;
        }

        if (!isset(self::$_explicitContexts[$user->id])) {
            return null;
        }

        $context = self::$_explicitContexts[$user->id];
        unset(self::$_explicitContexts[$user->id]);

        return $context;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns an existing state record for the user, or creates a new
     * unsaved one with the userId populated. The caller mutates and
     * saves; this helper centralises the find-or-instantiate logic so
     * every write path lands on the same shape.
     *
     * @param int $userId
     * @return UserStateRecord
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getOrCreateRecord(int $userId): UserStateRecord
    {
        $record = UserStateRecord::findOne(['userId' => $userId]);

        if ($record !== null) {
            return $record;
        }

        $record = new UserStateRecord();
        $record->userId = $userId;
        $record->uid = StringHelper::UUID();

        return $record;
    }
}
