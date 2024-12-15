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
 * Class PwnedValidator
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PwnedValidator extends Validator
{
    /**
     * @inheritdoc
     */
    public function validateValue($value): ?array
    {
        if (PasswordPolicy::$plugin->passwords->pwned($value)) {
            return [Craft::t('password-policy','This password has been compromised in a data breach. Please choose another password.'), []];
        }

        return null;
    }
}
