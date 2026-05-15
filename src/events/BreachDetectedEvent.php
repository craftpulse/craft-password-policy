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
     *     The prefix is k-anonymous in isolation — an attacker cannot reverse it
     *     to a unique password.
     *
     *     **Do not persist this value alongside `$user->id`.** A
     *     `(userId, prefix)` ledger — in a log file, audit row, or external
     *     observability system — recreates the linkability property the
     *     k-anonymity model is designed to prevent. Log "breach detected for
     *     user X" without the prefix, or log the prefix without the user, but
     *     never both as a paired record. The plugin's own HIBP-on-login dedup
     *     cache key omits the prefix for the same reason (commit 6703c88).
     */
    public string $sha1Prefix;

    /**
     * @var User the user whose password was found in the breach database
     */
    public User $user;
}
