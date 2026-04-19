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
 * Class MinimumCharacterTypesValidator
 *
 * Validates that a password contains at least N of 4 character types:
 * uppercase, lowercase, digit, symbol. Active only when complexityMode
 * is 'minimum'. Mutually exclusive with individual cases/numbers/symbols toggles.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class MinimumCharacterTypesValidator extends Validator
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
        $settings = PasswordPolicy::$plugin->getSettings();
        $required = $settings->minimumCharacterTypes;

        if ($required <= 0) {
            return null;
        }

        $count = 0;

        if (preg_match('/[A-Z]/', $value)) {
            $count++;
        }
        if (preg_match('/[a-z]/', $value)) {
            $count++;
        }
        if (preg_match('/[0-9]/', $value)) {
            $count++;
        }
        if (preg_match('/[^a-zA-Z0-9]/', $value)) {
            $count++;
        }

        if ($count < $required) {
            return [
                Craft::t(
                    'password-policy',
                    'Password must contain at least {count} of 4 character types (uppercase, lowercase, number, symbol).',
                    ['count' => $required],
                ),
                [],
            ];
        }

        return null;
    }
}
