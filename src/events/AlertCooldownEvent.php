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

use DateTime;
use yii\base\Event;

/**
 * Class AlertCooldownEvent
 *
 * Fired after `AlertCooldownService::recordFire()` writes a row to
 * `passwordpolicy_alert_cooldowns`. The fire decision has already been
 * made by the time this event triggers — listeners observe the fact, they
 * don't gate it. Use cases:
 *
 *  - SIEM forwarder mirroring the suppression record to off-site
 *    evidence (G8). An auditor walking the cooldowns history wants the
 *    same row visible in both places.
 *  - Compliance dashboard counting "alerts fired this week" /
 *    "suppressions this week" as a single read.
 *  - Custom integration recording the fire in a third-party incident
 *    queue.
 *
 * Edition: every — capture surface. Fires on Lite / Pro / Enterprise
 * because cooldowns themselves capture on every edition (memory rule
 * `project_audit_capture_principle.md`). Edition gates apply to read
 * surfaces (SIEM forwarder, dashboard) — they don't gate the event.
 *
 * @event AlertCooldownEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AlertCooldownEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var string the cooldown's dedup key — the second axis the
     *     `(eventClass, cooldownKey)` lookup keys on. Shape varies by
     *     event class: `user:<id>` for per-user windows, `event:<event>`
     *     for per-event-name windows, `prefix:<5char-sha1>` for HIBP
     *     bucket-level windows, etc.
     */
    public string $cooldownKey;

    /**
     * @var string the logical event class the cooldown was recorded
     *     against — e.g. `expiry_reminder`,
     *     `admin_security_alert:hibp_breach_detected`,
     *     `hibp_login_burst`, `group_deletion_cascade`. Stable
     *     identifier consumers can match on.
     */
    public string $eventClass;

    /**
     * @var DateTime UTC timestamp recorded on the
     *     `passwordpolicy_alert_cooldowns.firedAt` column. Authoritative
     *     for "when the alert fired" — listeners that need to correlate
     *     against external systems should use this rather than the
     *     listener's own clock read.
     */
    public DateTime $firedAt;
}
