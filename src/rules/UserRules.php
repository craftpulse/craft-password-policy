<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\rules;

use Craft;

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\validators\PasswordHistoryValidator;
use craftpulse\passwordpolicy\validators\PwnedValidator;

/**
 * Class UserRules
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class UserRules
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the validation rules for user password fields.
     *
     * @return array
     *
     * @author CraftPulse
     */
    public static function defineRules(): array
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        $rules[] =
            [
                ['password', 'newPassword'],
                'string',
                'min' => $settings->minLength,
                'tooShort' => Craft::t(
                    'password-policy',
                    'Password must contain at least {min} characters.',
                    ['min' => $settings->minLength]
                ),
                'skipOnError' => false,
            ];
        $rules[] =
            [
                ['password', 'newPassword'],
                'match',
                'pattern' => PasswordPolicy::$plugin->passwords->generatePattern(),
                'message' => Craft::t(
                        'password-policy',
                        'Your password must contain at least one of each of the following: '
                    ) . PasswordPolicy::$plugin->passwords->generateMessage(),
                'skipOnError' => false,
            ];

        if ($settings->maxLength > $settings->minLength) {
            $rules[] =
                [
                    ['password', 'newPassword'],
                    'string',
                    'max' => $settings->maxLength,
                    'tooLong' => Craft::t(
                        'password-policy',
                        'Password can maximum contain {max} characters.',
                        ['max' => $settings->maxLength]
                    ),
                    'skipOnError' => false,
                ];
        }

        if ($settings->pwned) {
            $rules[] = [
                ['password', 'newPassword'],
                PwnedValidator::class,
                'skipOnError' => false,
            ];
        }

        // Password history check (Pro+, gating handled inside validator)
        if ($settings->passwordHistoryCount > 0) {
            $rules[] = [
                ['password', 'newPassword'],
                PasswordHistoryValidator::class,
                'skipOnError' => false,
            ];
        }

        return $rules;
    }
}
