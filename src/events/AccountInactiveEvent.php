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
 * Class AccountInactiveEvent
 *
 * Fired by the Feature 5 (Pro) inactive-account scan after it actions a
 * dormant user — once per actioned user, regardless of which action mode
 * ran. Fires AFTER the action takes effect (the email was dispatched, or
 * the user was suspended), so listeners observe a settled state.
 *
 * The event fires on Pro (or higher) — the scan that drives it is a Pro
 * surface. Listeners can use it for their own observability (Slack alerts,
 * deprovisioning workflows, access-review tickets) without re-implementing
 * the detection query.
 *
 * Privacy: the payload carries the affected `User` element + the `action`
 * string (one of `report` | `notify` | `suspend`) — no password material,
 * no derived hashes.
 *
 * @event AccountInactiveEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AccountInactiveEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var string the action taken against the account: one of `report`,
     *     `notify`, or `suspend`.
     */
    public string $action;

    /**
     * @var User the dormant user the scan actioned.
     */
    public User $user;
}
