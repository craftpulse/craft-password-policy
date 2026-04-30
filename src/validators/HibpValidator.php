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
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\validators\Validator;

/**
 * Class HibpValidator
 *
 * Validates passwords against the HIBP Pwned Passwords database.
 * Supports fail-open (default) and fail-closed modes. Logs breach
 * detections and API failures to the audit log when available.
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
     */
    public function validateValue($value): ?array
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();
        $result = $plugin->getPasswords()->hibp($value);

        if ($result === true) {
            // Password found in breach database — log if Enterprise
            if ($plugin->getIsEnterprise() && $settings->enableAuditLog) {
                $plugin->getAuditLog()->logEvent(
                    userId: null,
                    event: 'hibp_breach_detected',
                    outcome: 'failure',
                );
            }

            return [
                Craft::t(
                    'password-policy',
                    'This password has been compromised in a data breach. Please choose another password.',
                ),
                [],
            ];
        }

        if ($result === null) {
            // API failure — log and respect fail mode
            if ($plugin->getIsEnterprise() && $settings->enableAuditLog) {
                $plugin->getAuditLog()->logEvent(
                    userId: null,
                    event: 'hibp_check_failed',
                    details: ['failMode' => $settings->hibpFailMode],
                    outcome: 'warning',
                );
            }

            if ($settings->hibpFailMode === 'closed') {
                return [
                    Craft::t(
                        'password-policy',
                        'Unable to verify password against breach database. Please try again later.',
                    ),
                    [],
                ];
            }

            // Fail-open: accept the password
            return null;
        }

        return null;
    }
}
