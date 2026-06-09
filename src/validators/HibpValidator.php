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

use Craft;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\validators\Validator;

/**
 * Class HibpValidator
 *
 * Validates passwords against the HIBP Pwned Passwords database.
 * Supports fail-open (default) and fail-closed modes. Logs breach
 * detections and API failures to the audit log when available.
 *
 * Overrides `validateAttribute()` rather than `validateValue()` so the
 * model under validation is in scope — breach / check-failed audit rows
 * capture the originating user id (`$model instanceof User ? $model->id
 * : null`) instead of always recording `userId: null`. Mirrors
 * {@see PasswordHistoryValidator}. Wired against the `password` /
 * `newPassword` attributes in {@see \craftpulse\passwordpolicy\rules\UserRules}.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class HibpValidator extends Validator
{
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
        $value = $model->$attribute;

        if (empty($value)) {
            return;
        }

        $error = $this->_check($value, $this->_userIdFrom($model));

        if ($error !== null) {
            $this->addError($model, $attribute, $error);
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Runs the HIBP check for `$password` and returns a translated error
     * message when the password must be rejected, or null when it passes
     * (clean, or fail-open on an API failure). Records the appropriate
     * audit row with the resolved `$userId` — capture is universal (G1);
     * the service's `enableAuditLog` toggle is the only gate.
     *
     * @param string $password
     * @param int|null $userId the originating user id, null for an
     *     anonymous / new-user context
     * @return string|null translated rejection message, or null to accept
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _check(#[\SensitiveParameter] string $password, ?int $userId): ?string
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();
        $result = $plugin->getPasswords()->hibp($password);

        if ($result === true) {
            // Password found in breach database — record the audit row.
            $plugin->getAuditLog()->logEvent(
                userId: $userId,
                event: 'hibp_breach_detected',
                outcome: 'failure',
            );

            return Craft::t(
                'password-policy',
                'This password has been compromised in a data breach. Please choose another password.',
            );
        }

        if ($result === null) {
            // API failure — record the audit row, then respect fail mode.
            $plugin->getAuditLog()->logEvent(
                userId: $userId,
                event: 'hibp_check_failed',
                details: ['failMode' => $settings->hibpFailMode],
                outcome: 'warning',
            );

            if ($settings->hibpFailMode === 'closed') {
                return Craft::t(
                    'password-policy',
                    'Unable to verify password against breach database. Please try again later.',
                );
            }

            // Fail-open: accept the password.
            return null;
        }

        return null;
    }

    /**
     * Resolves the originating user id from the model under validation.
     * Returns the user id when the model is a saved `User`, null
     * otherwise (new user with no id, or a non-User model).
     *
     * @param mixed $model
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _userIdFrom(mixed $model): ?int
    {
        return $model instanceof User && $model->id ? (int)$model->id : null;
    }
}
