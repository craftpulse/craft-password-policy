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

/**
 * Enum InactiveAction
 *
 * Closed set of actions the inactive-account scan (Feature 5, Pro) takes
 * against an account that has crossed the inactivity threshold. Backs the
 * `inactiveAction` setting key and the `--action` override on
 * `password-policy/inactive/scan`.
 *
 * The default — {@see self::Report} — is deliberately non-destructive so a
 * fresh install never locks a dormant user out by surprise. The PCI-DSS and
 * Strict Enterprise compliance presets opt INTO {@see self::Suspend} at a
 * 90-day threshold (PCI-DSS v4.0 §8.2.6 mandates disabling inactive accounts
 * within 90 days); the NIST / OWASP presets leave the safe default in place.
 *
 * `suspend` uses Craft's NATIVE suspension (`User::$suspended = true`) — a
 * reversible state, never a deletion. Pending-user purge stays Craft core's
 * job (`purgePendingUsersDuration`); this feature targets ACTIVE dormant
 * accounts.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
enum InactiveAction: string
{
    /**
     * Report-only — flag the account in the CP report surface, send no
     * email, change no state. The safe default on a fresh install.
     */
    case Report = 'report';

    /**
     * Notify — email the dormant user (the seeded `inactive-account`
     * template), optionally alert the admin, change no account state.
     */
    case Notify = 'notify';

    /**
     * Suspend — set `User::$suspended = true` via Craft's native
     * suspension. Reversible. Opted into by the PCI-DSS + Strict presets.
     */
    case Suspend = 'suspend';

    // Public Methods
    // =========================================================================

    /**
     * Returns a human-readable label for the action. Used in the CP report
     * surface and console output.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function label(): string
    {
        return match ($this) {
            self::Report => 'Report only',
            self::Notify => 'Notify user',
            self::Suspend => 'Suspend account',
        };
    }

    // Static Methods
    // =========================================================================

    /**
     * Returns every enum value as a flat array of strings. Used by the
     * `SettingsModel` validation range and by the console `--action`
     * override guard.
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
}
