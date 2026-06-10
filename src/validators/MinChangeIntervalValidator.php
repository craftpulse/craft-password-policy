<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\validators;

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\validators\Validator;

/**
 * Class MinChangeIntervalValidator
 *
 * Blocks a user from re-changing their password within N hours of their
 * last change. Closes the "cycle N+1 password changes to flush the reuse
 * history" evasion. Pro feature; per-group overridable.
 *
 * Resolution-hazard contract (`project_per_group_resolution_hazard.md`):
 * the validator enforces the RESOLVED per-user interval threaded in via
 * `UserRules::defineRules()` ({@see self::$minChangeIntervalHours}) — it
 * does NOT re-read `PasswordPolicy::$plugin->getSettings()`. A per-group
 * override of 24h enforces even when the global is disabled (0). The
 * global fallback applies only when no resolved value was threaded
 * (AJAX/preview contexts without a target user).
 *
 * Forced-reset bypass: admin force-reset, first-login forced, expiry
 * forced, and HIBP breach forced changes are exempt — the system can't
 * tell a user "you changed too recently" when the system itself forced
 * the change. The pending reason is read from the same
 * `passwordpolicy_user_state.pendingResetReason` source the central
 * history-write listener consumes (`PasswordPolicy::_resolveAuditContext()`
 * Tier 2). A normal self-service or admin-set change IS subject to the
 * interval.
 *
 * "Last change" reads the canonical `users.lastPasswordChangeDate`
 * column (always maintained by Craft) rather than the plugin history
 * table (only written when `passwordHistoryCount > 0`). `UserQuery`
 * doesn't `addSelect()` that column, so it's read via a direct scalar
 * `Query` against `Table::USERS` — the same idiom
 * `UserSecurityController` / `UserPasswordController` use.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class MinChangeIntervalValidator extends Validator
{
    // Public Properties
    // =========================================================================

    /**
     * @var bool
     */
    public $skipOnError = false;

    /**
     * Resolved per-user minimum change interval, in hours. Set by
     * `UserRules::defineRules()` from the user's effective policy so a
     * per-group override is enforced at save. Null falls back to the
     * global `SettingsModel` value (AJAX/preview contexts without a
     * target user).
     *
     * @var int|null
     */
    public ?int $minChangeIntervalHours = null;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateAttribute($model, $attribute): void
    {
        $plugin = PasswordPolicy::$plugin;

        // Resolved per-user interval wins; fall back to global only when unset.
        $hours = $this->minChangeIntervalHours
            ?? $plugin->getSettings()->minChangeIntervalHours;

        // Feature gate — disabled at 0 (or any non-positive value).
        if ($hours <= 0) {
            return;
        }

        $password = $model->$attribute;
        if (empty($password)) {
            return;
        }

        // Only existing users have a last-change timestamp to compare against.
        if (!$model instanceof User || !$model->id) {
            return;
        }

        // Forced resets bypass the interval — the system can't fault a user
        // for a change it forced. Read the pending reason from the same
        // user_state source the history-write listener consumes.
        if ($this->_isForcedReset($model)) {
            return;
        }

        $lastChange = $this->_lastPasswordChangeDate($model->id);

        // Never-changed user (null lastPasswordChangeDate) — nothing to
        // compare against; allow the change.
        if ($lastChange === null) {
            return;
        }

        $allowedAt = Carbon::instance($lastChange)->utc()->addHours($hours);

        if (Carbon::now('UTC')->greaterThanOrEqualTo($allowedAt)) {
            return;
        }

        $this->addError(
            $model,
            $attribute,
            Craft::t(
                'password-policy',
                'You changed your password too recently; you can change it again after {time}.',
                ['time' => Craft::$app->getFormatter()->asDatetime($allowedAt, 'short')],
            ),
        );
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether the user has a pending forced-reset reason that
     * exempts the change from the interval. Mirrors Tier 2 of
     * `PasswordPolicy::_resolveAuditContext()` — reads
     * `passwordpolicy_user_state.pendingResetReason` without consuming
     * the single-use explicit-context slot (which the history-write
     * listener owns).
     *
     * @param User $user
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _isForcedReset(User $user): bool
    {
        $state = PasswordPolicy::$plugin->getUserState()->getStateForUser($user);

        if ($state === null || $state->pendingResetReason === null) {
            return false;
        }

        $reason = ChangeReason::tryFrom($state->pendingResetReason);

        return in_array($reason, [
            ChangeReason::AdminForceReset,
            ChangeReason::FirstLoginForced,
            ChangeReason::ExpiryForced,
            ChangeReason::BreachForced,
        ], true);
    }

    /**
     * Reads the user's `lastPasswordChangeDate` via a direct scalar
     * query. `craft\elements\db\UserQuery::beforePrepare()` does not
     * `addSelect()` this column, so a freshly-loaded `User` element
     * carries `null` — the value must come straight from the users
     * table.
     *
     * @param int $userId
     * @return \DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _lastPasswordChangeDate(int $userId): ?\DateTime
    {
        $value = (new Query())
            ->select(['lastPasswordChangeDate'])
            ->from(Table::USERS)
            ->where(['id' => $userId])
            ->scalar();

        if (empty($value)) {
            return null;
        }

        return DateTimeHelper::toDateTime($value) ?: null;
    }
}
