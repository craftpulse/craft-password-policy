<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
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
 * The regex carries the `/u` modifier so the matcher operates on Unicode
 * code points, not raw bytes. Non-ASCII repeats (`ααα`, `еее`, emoji
 * runs) are caught the same way ASCII repeats are — an admin enabling
 * the rule expects "no character repeated three times" to mean what
 * the user sees, not what their keyboard encoded as bytes.
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
    public function validateValue(#[\SensitiveParameter] $value): ?array
    {
        if (preg_match('/(.)\1{2,}/u', $value)) {
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
