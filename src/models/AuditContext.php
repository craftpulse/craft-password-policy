<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use Craft;
use craftpulse\passwordpolicy\enums\ChangeReason;

/**
 * Class AuditContext
 *
 * Immutable bag of audit-trail metadata attached to a password change.
 * Threads through {@see \craftpulse\passwordpolicy\services\PasswordHistoryService::savePasswordHash()}
 * so every history row records who did the change, when, and over which
 * transport. Phase D1 walks every change site and threads the
 * appropriate context through; D0 (this build) defines the surface and
 * wires the migration-seed call site as the proof-of-shape.
 *
 * Capture is non-negotiable across editions — every edition writes the
 * full audit context. Edition gates apply to UI, API, and SIEM exposure
 * downstream of the captured row, never to the row itself.
 *
 * Constructor is publicly callable for advanced cases; prefer the named
 * factories ({@see self::selfService()}, {@see self::adminChange()},
 * etc.) at every call site for readability and to keep the per-reason
 * defaults consistent.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
final class AuditContext
{
    // Public Methods
    // =========================================================================

    /**
     * Constructs an audit context. Prefer the named factories below at
     * call sites.
     *
     * @param ChangeReason $reason
     * @param int|null $changedByUserId the admin/operator user ID, or null
     *     if the change was triggered by the user themselves, a CLI run,
     *     or a migration
     * @param string|null $sourceIp the request IP at change time
     * @param string|null $userAgent the request user-agent at change time
     * @param string|null $policySnapshot the policy ID/handle that was
     *     active at change time; resolver service interprets the format
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        public readonly ChangeReason $reason,
        public readonly ?int $changedByUserId = null,
        public readonly ?string $sourceIp = null,
        public readonly ?string $userAgent = null,
        public readonly ?string $policySnapshot = null,
    ) {
    }

    // Static Methods
    // =========================================================================

    /**
     * Builds a context from the active web request — pulls IP + UA off
     * `Craft::$app->getRequest()` if available. Falls back to a
     * request-less context (no IP/UA) when running outside web scope
     * (queue worker, console run, migration).
     *
     * @param ChangeReason $reason
     * @param int|null $changedByUserId
     * @param string|null $policySnapshot
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRequest(
        ChangeReason $reason,
        ?int $changedByUserId = null,
        ?string $policySnapshot = null,
    ): self {
        $sourceIp = null;
        $userAgent = null;

        $request = Craft::$app->getRequest();

        if (!$request->getIsConsoleRequest()) {
            // userIP returns null when the request lacks a remote addr —
            // common in CLI-via-php-fpm-mocking and other test paths.
            $sourceIp = $request->getUserIP();
            $userAgent = $request->getUserAgent();
        }

        return new self(
            reason: $reason,
            changedByUserId: $changedByUserId,
            sourceIp: $sourceIp,
            userAgent: $userAgent,
            policySnapshot: $policySnapshot,
        );
    }

    /**
     * The user changed their own password through a normal flow — front-
     * end builder, login change form, account screen.
     *
     * @param string|null $policySnapshot
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function selfService(?string $policySnapshot = null): self
    {
        return self::fromRequest(
            reason: ChangeReason::SelfService,
            policySnapshot: $policySnapshot,
        );
    }

    /**
     * An admin changed another user's password through an authenticated
     * CP action.
     *
     * @param int $changedByUserId the acting admin's user ID
     * @param string|null $policySnapshot
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function adminChange(int $changedByUserId, ?string $policySnapshot = null): self
    {
        return self::fromRequest(
            reason: ChangeReason::AdminChange,
            changedByUserId: $changedByUserId,
            policySnapshot: $policySnapshot,
        );
    }

    /**
     * HIBP-on-login (Pro) detected a breach. The user is being forced to
     * reset at next login. No `changedByUserId` — the system, not an
     * admin, is the operator.
     *
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function breachForced(): self
    {
        return self::fromRequest(reason: ChangeReason::BreachForced);
    }

    /**
     * Migration seed — used by `_seedPasswordHistory()` during the
     * 5.1.1 → 5.2.0 upgrade. No request scope (running mid-migration),
     * no acting user.
     *
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function migrationSeed(): self
    {
        return new self(reason: ChangeReason::MigrationSeed);
    }

    /**
     * CLI-driven change — `users/set-password` and friends. No acting
     * user (the OS user running PHP is meaningless to the audit record;
     * the {@see ChangeReason::Cli} marker is what matters).
     *
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function cli(): self
    {
        return new self(reason: ChangeReason::Cli);
    }
}
