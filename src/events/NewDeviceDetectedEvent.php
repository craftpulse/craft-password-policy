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
 * Class NewDeviceDetectedEvent
 *
 * Fired by the Feature 1 login listener after a login from a device
 * fingerprint that has no prior row for the user — i.e. immediately after
 * `DeviceTrackingService::recordLogin()` reports a new device and writes
 * the `passwordpolicy_known_devices` row.
 *
 * The event fires on EVERY edition (it is a free ecosystem hook — capture
 * is universal per `project_audit_capture_principle.md`), regardless of
 * whether the Enterprise-gated new-device alert email is sent. Listeners
 * can use it for their own observability (Slack alerts, custom audit
 * trails, MFA step-up triggers) without re-implementing the fingerprinting
 * or the privacy masking.
 *
 * Privacy: the payload carries only the MASKED IP and the human-readable
 * device label — never the raw user-agent, raw IP, or the fingerprint.
 * Persisting the fingerprint alongside the user recreates a linkable
 * device ledger; the masked label is the safe display surface.
 *
 * @event NewDeviceDetectedEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NewDeviceDetectedEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var string the human-readable device label (e.g. "Chrome on
     *     macOS"), optionally suffixed with a geo hint. Never the raw
     *     user-agent.
     */
    public string $deviceLabel;

    /**
     * @var string the source IP with the last IPv4 octet zeroed / IPv6
     *     truncated to /64. Never the raw IP.
     */
    public string $maskedIp;

    /**
     * @var int|null the site the login happened on, or null.
     */
    public ?int $siteId = null;

    /**
     * @var User the user who logged in from the new device.
     */
    public User $user;
}
