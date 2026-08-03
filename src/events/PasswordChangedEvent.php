<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\events;

use craft\elements\User;
use yii\base\Event;

/**
 * Class PasswordChangedEvent
 *
 * Fired after a password has been successfully changed and history stored.
 * By the time this event fires, newPassword is already null — the plaintext
 * is gone. This event intentionally does NOT contain the password or any hash.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordChangedEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var User the user whose password was changed (newPassword is null)
     */
    public User $user;

    /**
     * @var bool whether this is a newly created user
     */
    public bool $isNew = false;
}
