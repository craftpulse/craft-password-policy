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
use yii\validators\Validator;

/**
 * Class RepeatedCharsValidator
 *
 * Detects 3+ consecutive repeated characters in passwords (e.g., aaa, 111, !!!).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class RepeatedCharsValidator extends Validator
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateValue($value): ?array
    {
        if (preg_match('/(.)\1{2,}/', $value)) {
            return [
                Craft::t(
                    'password-policy',
                    'Password must not contain 3 or more repeated characters in a row.',
                ),
                [],
            ];
        }

        return null;
    }
}
