<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\events;

use craft\elements\User;
use yii\base\Event;

/**
 * Class PasswordValidationEvent
 *
 * Fired after all built-in validators have run, allowing third-party
 * modules to add custom validation rules. The plaintext password is
 * intentionally NOT included in this event.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordValidationEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var User the user whose password is being validated
     */
    public User $user;

    /**
     * @var string[] validation error messages from built-in rules
     */
    public array $errors = [];

    /**
     * @var bool whether the password passed all built-in validation
     */
    public bool $isValid = true;
}
