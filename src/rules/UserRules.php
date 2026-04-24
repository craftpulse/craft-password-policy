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
use craftpulse\passwordpolicy\validators\CommonPasswordValidator;
use craftpulse\passwordpolicy\validators\ContextualValidator;
use craftpulse\passwordpolicy\validators\MinimumCharacterTypesValidator;
use craftpulse\passwordpolicy\validators\PasswordHistoryValidator;
use craftpulse\passwordpolicy\validators\PwnedValidator;
use craftpulse\passwordpolicy\validators\RepeatedCharsValidator;
use craftpulse\passwordpolicy\validators\SequentialCharsValidator;

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
        $isPro = PasswordPolicy::$plugin->getIsPro();

        // Min length (always)
        $rules[] = [
            ['password', 'newPassword'],
            'string',
            'min' => $settings->minLength,
            'tooShort' => Craft::t(
                'password-policy',
                'Password must contain at least {min} characters.',
                ['min' => $settings->minLength],
            ),
            'skipOnError' => false,
        ];

        // Complexity: individual toggles or minimum character types
        if ($isPro && $settings->complexityMode === 'minimum' && $settings->minimumCharacterTypes > 0) {
            // "X of 4 character types" mode — mutually exclusive with individual toggles
            $rules[] = [
                ['password', 'newPassword'],
                MinimumCharacterTypesValidator::class,
                'skipOnError' => false,
            ];
        } else {
            // Individual toggle mode (default)
            $rules[] = [
                ['password', 'newPassword'],
                'match',
                'pattern' => PasswordPolicy::$plugin->getPasswords()->generatePattern(),
                'message' => Craft::t(
                        'password-policy',
                        'Your password must contain at least one of each of the following: ',
                    ) . PasswordPolicy::$plugin->getPasswords()->generateMessage(),
                'skipOnError' => false,
            ];
        }

        // Max length
        if ($settings->maxLength > $settings->minLength) {
            $rules[] = [
                ['password', 'newPassword'],
                'string',
                'max' => $settings->maxLength,
                'tooLong' => Craft::t(
                    'password-policy',
                    'Password can maximum contain {max} characters.',
                    ['max' => $settings->maxLength],
                ),
                'skipOnError' => false,
            ];
        }

        // Sequential characters (Pro+)
        if ($isPro && $settings->checkSequentialChars) {
            $rules[] = [
                ['password', 'newPassword'],
                SequentialCharsValidator::class,
                'skipOnError' => false,
            ];
        }

        // Repeated characters (Pro+)
        if ($isPro && $settings->checkRepeatedChars) {
            $rules[] = [
                ['password', 'newPassword'],
                RepeatedCharsValidator::class,
                'skipOnError' => false,
            ];
        }

        // Contextual check (Pro+)
        if ($isPro && $settings->checkContextual) {
            $rules[] = [
                ['password', 'newPassword'],
                ContextualValidator::class,
                'skipOnError' => false,
            ];
        }

        // Common password blocklist (Pro+)
        if ($isPro && $settings->checkCommonPasswords) {
            $rules[] = [
                ['password', 'newPassword'],
                CommonPasswordValidator::class,
                'skipOnError' => false,
            ];
        }

        // HIBP check (after content rules — external API call, slower)
        if ($settings->pwned) {
            $rules[] = [
                ['password', 'newPassword'],
                PwnedValidator::class,
                'skipOnError' => false,
            ];
        }

        // Password history check last (Pro+, gating handled inside validator)
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
