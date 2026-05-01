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
use DateTime;
use yii\base\Event;

/**
 * Class BreachDetectedEvent
 *
 * Fired when the HIBP-on-login listener detects that a user's plaintext
 * password matches an entry in the Pwned Passwords k-anonymity bucket. The
 * event payload deliberately omits the plaintext, the full SHA-1 hash, and
 * the suffix half of the prefix-and-suffix bucket — only the 5-char prefix
 * is exposed (k-anonymity safe, allowed to surface for diagnostics).
 *
 * Listeners can use this hook for their own observability — SIEM forwarding,
 * Slack alerts, custom audit trails — without having to re-implement the
 * privacy guards.
 *
 * @event BreachDetectedEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BreachDetectedEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var DateTime when the breach was detected (server time)
     */
    public DateTime $detectedAt;

    /**
     * @var string the SHA-1 prefix (5 characters, uppercase) submitted to HIBP.
     *     Safe to log and forward — k-anonymity guarantees an attacker cannot
     *     reverse the prefix to a unique password.
     */
    public string $sha1Prefix;

    /**
     * @var User the user whose password was found in the breach database
     */
    public User $user;
}
