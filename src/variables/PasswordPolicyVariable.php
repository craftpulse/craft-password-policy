<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\variables;

use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateTime;
use nystudio107\pluginvite\variables\ViteVariableInterface;
use nystudio107\pluginvite\variables\ViteVariableTrait;

/**
 * Class PasswordPolicyVariable
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordPolicyVariable implements ViteVariableInterface
{
    use ViteVariableTrait;

    // Public Methods
    // =========================================================================

    /**
     * Returns the number of days until the current user's password expires.
     *
     * @return int|null null if no expiration configured or no user logged in
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function daysUntilExpiry(): ?int
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return null;
        }

        $expiryDate = $this->_getExpiryDate($user);

        if ($expiryDate === null) {
            return null;
        }

        $now = new DateTime();
        $diff = $now->diff($expiryDate);

        return $diff->invert ? 0 : $diff->days;
    }

    /**
     * Returns whether the current user's password is past expiration.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isExpired(): bool
    {
        $days = $this->daysUntilExpiry();

        return $days !== null && $days <= 0;
    }

    /**
     * Returns whether the current user's password expires within the given window.
     *
     * @param int $days
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isExpiring(int $days = 14): bool
    {
        $remaining = $this->daysUntilExpiry();

        if ($remaining === null) {
            return false;
        }

        return $remaining > 0 && $remaining <= $days;
    }

    /**
     * Returns the password status for the current user.
     *
     * @return string One of: current, expiring, expired, reset_required, never_changed, unknown
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function passwordStatus(): string
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return 'unknown';
        }

        if ($user->passwordResetRequired) {
            return 'reset_required';
        }

        if ($user->lastPasswordChangeDate === null) {
            return 'never_changed';
        }

        if ($this->isExpired()) {
            return 'expired';
        }

        if ($this->isExpiring()) {
            return 'expiring';
        }

        return 'current';
    }

    /**
     * Returns the current user's last password change date.
     *
     * @return DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function lastPasswordChange(): ?DateTime
    {
        $user = $this->_getCurrentUser();

        return $user?->lastPasswordChangeDate;
    }

    /**
     * Returns the number of active sessions for the current user.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function activeSessionCount(): int
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return 0;
        }

        return (int)(new Query())
            ->from(Table::SESSIONS)
            ->where(['userId' => $user->id])
            ->count();
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the currently logged-in user.
     *
     * @return User|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getCurrentUser(): ?User
    {
        /** @var User|null */
        return Craft::$app->getUser()->getIdentity();
    }

    /**
     * Calculates the password expiry date for a user based on settings.
     *
     * @param User $user
     * @return DateTime|null null if no expiration configured
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getExpiryDate(User $user): ?DateTime
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $lastChange = $user->lastPasswordChangeDate;

        if ($lastChange === null) {
            return null;
        }

        $expiry = clone $lastChange;

        $interval = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => 'P' . ($settings->expiryAmount * 7) . 'D',
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => "P{$settings->expiryAmount}D",
        };

        $expiry->add(new \DateInterval($interval));

        return $expiry;
    }
}
