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
 * Class GroupAlertDispatchedEvent
 *
 * Fired by the Feature 3 per-group alert routing (Pro) after a COPY of a
 * `breach_detected` / `new_device` alert is dispatched to a group-designated
 * security contact — once per recipient that cleared the per-group cooldown.
 * It does NOT fire for the end-user's own alert (that is the
 * `breach_detected` / `new_device` notification surface), nor for recipients
 * suppressed by the cooldown.
 *
 * The event fires only on Pro (or higher) — per-group alerts are a Pro
 * surface — and only when at least one recipient resolves from the affected
 * user's group set. Listeners can use it for their own observability (SIEM
 * mirroring, incident-queue integration) without re-implementing the
 * resolution or the cooldown throttling.
 *
 * Privacy: the payload carries the user element (the listener that already
 * has the in-scope user can correlate), the resolving `groupId`, the
 * `eventType`, and the `recipientEmail` — never any password material.
 *
 * @event GroupAlertDispatchedEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupAlertDispatchedEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var string the alert event type routed — `breach_detected` or
     *     `new_device`.
     */
    public string $eventType;

    /**
     * @var int the user group whose subscription resolved this recipient.
     */
    public int $groupId;

    /**
     * @var string the security-contact email the alert copy was routed to.
     */
    public string $recipientEmail;

    /**
     * @var User the user who triggered the originating alert.
     */
    public User $user;
}
