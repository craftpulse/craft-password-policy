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
    public static function defineRules(): array
    {
        $settings = PasswordPolicy::$plugin->settings;

        $rules[] =
        [
            ['password', 'newPassword'],
            'string',
            'min' => $settings->minLength,
            'tooShort' => Craft::t(
                'password-policy',
                Craft::t('password-policy','Password must contain at least {min} characters.'),
                ['min' => $settings->minLength]
            ),
        ];
        $rules[] =
        [
            ['password', 'newPassword'],
            'string',
            'max' => $settings->maxLength,
            'tooLong' => Craft::t(
                'password-policy',
                Craft::t('password-policy','Password can maximum contain {max} characters.'),
                ['max' => $settings->maxLength]
            ),
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
        ];

        if ($settings->pwned) {
            $rules[] = [['password', 'newPassword'], PwnedValidator::class];
        }

        return $rules;
    }
}
