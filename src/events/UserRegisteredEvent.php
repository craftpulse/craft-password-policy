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
 * Class UserRegisteredEvent
 *
 * Fired by `RegistrationService::register()` after a user has been successfully
 * created, assigned to groups, and (optionally) sent an activation email. The
 * plaintext password is intentionally NOT included — the password has already
 * been validated and persisted by this point and the plaintext is gone.
 *
 * Distinguished from a direct `Craft::$app->elements->saveElement($user)` call
 * by the `viaService` flag — listeners can choose to act only on registrations
 * that flowed through the plugin's service entry point.
 *
 * @event UserRegisteredEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserRegisteredEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var User the persisted user element
     */
    public User $user;

    /**
     * @var string[] the group handles that were assigned at registration time
     */
    public array $groups = [];

    /**
     * @var bool whether the registration flowed through `RegistrationService::register()`.
     *     Always true when fired by the service. Reserved for future use by
     *     listeners that may want to distinguish service-driven registrations
     *     from direct element-save invocations.
     */
    public bool $viaService = true;
}
