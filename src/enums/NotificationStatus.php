<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\enums;

use Craft;
use craft\enums\Color;

/**
 * Enum NotificationStatus
 *
 * Closed set of outcomes for a notification send attempt. Drives the
 * `passwordpolicy_notification_log.status` column and the activity
 * surface's filter / pill rendering. The column is `varchar(16)` —
 * the PHP enum is the canonical validator; cross-DB driver detection
 * for an `ENUM` type at the DB level isn't worth the migration
 * complexity at this scale.
 *
 * Capture is non-negotiable across editions — `NotificationService`
 * writes a row per send attempt regardless of outcome. Edition gates
 * apply to the activity-surface CP screen (Pro+ subnav), not to the
 * underlying capture.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
enum NotificationStatus: string
{
    /**
     * Mailer's `send()` returned without throwing. The recipient
     * server accepted the message at SMTP — provider-side bounces
     * (asynchronous) are not in scope; see `ideas.md` for the bounce-
     * ingestion deferral.
     */
    case Sent = 'sent';

    /**
     * Mailer's `send()` (or upstream Twig template render) threw. The
     * `errorMessage` column captures `Throwable::getMessage()`. Common
     * cases: SMTP refused, malformed recipient, transient transport
     * outage, syntax error in an admin-edited template.
     */
    case Failed = 'failed';

    // Static Methods
    // =========================================================================

    /**
     * Returns every enum value as a flat array of strings. Used by
     * filter dropdowns on the activity index + by validators that
     * accept the status as a string from request payloads.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function values(): array
    {
        return array_column(self::cases(), 'value');
    }

    // Public Methods
    // =========================================================================

    /**
     * Returns a human-readable label for the status. Used in the CP
     * activity index + per-user panel rendering, and in any future
     * SIEM forwarder payload (Phase G).
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function label(): string
    {
        return match ($this) {
            self::Sent => Craft::t('password-policy', 'Sent'),
            self::Failed => Craft::t('password-policy', 'Failed'),
        };
    }

    /**
     * Returns the `Color` case used to render this status as a pill
     * via `Cp::statusLabelHtml()` in the activity index. Failed rows
     * surface red; sent rows surface green for visual parity with
     * Craft's native element-status idiom.
     *
     * @return Color
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function color(): Color
    {
        return match ($this) {
            self::Sent => Color::Green,
            self::Failed => Color::Red,
        };
    }
}
