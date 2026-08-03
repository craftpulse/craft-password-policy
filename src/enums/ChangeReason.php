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
 * Enum ChangeReason
 *
 * Closed set of reasons a password change row was written. Drives the
 * `passwordpolicy_password_history.changeReason` and
 * `passwordpolicy_user_state.pendingResetReason` columns. The PHP enum
 * is the single source of truth — the migration reads
 * {@see self::values()} at runtime to build the database `ENUM` (MySQL)
 * or `CHECK` constraint (PostgreSQL).
 *
 * **Adding a case requires a follow-up migration** that runs
 * `ALTER TABLE ... MODIFY changeReason ENUM(...)` (or the equivalent
 * PostgreSQL constraint refresh) with the extended value list. Forgetting
 * this step manifests as a SQL error the first time the new case is
 * inserted, not at deploy time. Document the new case + the migration in
 * the same commit.
 *
 * Capture is non-negotiable across editions — every change site populates
 * the `changeReason` column on every edition. Edition gates belong on the
 * UI/API/SIEM exposure path, not on the schema or service write path.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
enum ChangeReason: string
{
    /**
     * User changed their own password through the standard flow (login
     * change form, account screen, front-end builder).
     */
    case SelfService = 'self_service';

    /**
     * Admin changed another user's password through an authenticated CP
     * action (P2.2 element action, edit-screen save).
     */
    case AdminChange = 'admin_change';

    /**
     * Admin marked another user as needing to reset their password on
     * next login. Distinct from {@see self::AdminChange} — no new
     * password was set, only the reset flag flipped.
     */
    case AdminForceReset = 'admin_force_reset';

    /**
     * New-user-created flow flipped `passwordResetRequired` so the user
     * is forced through a change at first login. Fires from
     * {@see \craftpulse\passwordpolicy\PasswordPolicy::_registerPasswordHistoryListeners()}'s
     * `forceChangeOnFirstLogin` branch.
     */
    case FirstLoginForced = 'first_login_forced';

    /**
     * Expiry policy elapsed — the user is forced to change at next login
     * because their previous password aged past the configured limit.
     */
    case ExpiryForced = 'expiry_forced';

    /**
     * HIBP-on-login (Pro) detected a breach. Password was found in the
     * Have I Been Pwned database; the user is forced to change at next
     * login. Fires from the `User::EVENT_BEFORE_AUTHENTICATE` listener.
     */
    case BreachForced = 'breach_forced';

    /**
     * Password change was driven by a CLI command (`users/set-password`,
     * `password-policy/notification/send-expiry-reminders`, etc.) rather
     * than a web request. No `changedByUserId` is captured for CLI runs.
     */
    case Cli = 'cli';

    /**
     * Migration seeded the row from existing user password hashes during
     * the 5.1.1 → 5.2.0 upgrade. No `changedByUserId` and no IP/UA
     * because no human triggered the write — the migration is the
     * source.
     */
    case MigrationSeed = 'migration_seed';

    // Public Methods
    // =========================================================================

    /**
     * Returns a human-readable label for the reason. Used in CP UI
     * (Phase D2 condition rules + D4 user-edit tab) and in audit-log
     * exports (Phase G).
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function label(): string
    {
        return match ($this) {
            self::SelfService => 'Self-service change',
            self::AdminChange => 'Admin change',
            self::AdminForceReset => 'Admin forced reset',
            self::FirstLoginForced => 'First-login forced reset',
            self::ExpiryForced => 'Expiry forced reset',
            self::BreachForced => 'Breach-forced reset',
            self::Cli => 'CLI',
            self::MigrationSeed => 'Migration seed',
        };
    }

    // Static Methods
    // =========================================================================

    /**
     * Returns every enum value as a flat array of strings. Used by the
     * migration to build the `ENUM(...)` / `CHECK (... IN (...))` column
     * type and by validators to constrain inputs.
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
