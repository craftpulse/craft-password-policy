<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\integrations;

use Craft;
use craftpulse\authkit\audit\AuditSinkInterface;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use Throwable;

/**
 * Class AuthKitAuditSink
 *
 * Password Policy's adapter for Auth Kit's audit-event contract. Warden and
 * Warp emit neutral {@see AuthEvent} value objects through Auth Kit's `audit`
 * service on every passwordless / SSO / SCIM flow; this sink receives them and
 * lands each on PP's hash-chained, SIEM-forwarded audit log via
 * {@see AuditLogService::logEvent()}. From there the row flows to the SIEM
 * forwarders, compliance dashboard, exports, and tamper-evident chain with zero
 * additional work — the payoff of designing against `logEvent()`.
 *
 * No hard dependency
 * ------------------
 * PP `suggest`s Auth Kit, never `require`s it. This class only autoloads when
 * the registration closure in `PasswordPolicy::_registerAuditKitSink()`
 * instantiates it, and that closure only runs when Auth Kit is installed and
 * fires `Audit::EVENT_REGISTER_AUDIT_SINKS`. With Auth Kit absent the closure
 * never runs, this class never loads, and there is no fatal — `Audit::class` in
 * the `Event::on()` call is a compile-time string that autoloads nothing.
 *
 * Neutral-name mapping
 * --------------------
 * {@see EVENT_MAP} translates each frozen {@see AuthEvent} name onto a PP event
 * class. The four `login.*` names collapse onto `auth_login`; the login method
 * (`magic_link` | `otp` | `passkey` | `sso`) is recovered from the neutral
 * name's suffix and carried in `details.method`. Names absent from the map are
 * ignored silently — the forward-compatibility contract: Auth Kit adds names in
 * minors, and a sink built against an older vocabulary must tolerate a newer
 * emitter.
 *
 * Fail-soft
 * ---------
 * `handle()` never throws. Auth Kit's `Audit::record()` already wraps every sink
 * in its own try/catch, and `logEvent()` swallows its own writes — but per PP's
 * defensive style this sink still catches anything itself (belt and braces) so a
 * mapping bug can never derail an auth flow.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuthKitAuditSink implements AuditSinkInterface
{
    // Const Properties
    // =========================================================================

    /**
     * Maps each neutral {@see AuthEvent} name onto the PP event class the row
     * is written under. Every value MUST have a matching key in
     * {@see AuditLogService::ALLOWED_DETAILS_BY_EVENT} — `AuditAllowlistRegistryTest`
     * asserts exactly that, standing in for the codebase-grep test (which can't
     * see the mapped variable this sink passes to `logEvent()`).
     *
     * Public so the registry test and any inspection surface can read the
     * contract in one place.
     *
     * @var array<string, string>
     */
    public const EVENT_MAP = [
        AuthEvent::LOGIN_MAGIC_LINK => 'auth_login',
        AuthEvent::LOGIN_OTP => 'auth_login',
        AuthEvent::LOGIN_PASSKEY => 'auth_login',
        AuthEvent::LOGIN_SSO => 'auth_login',
        AuthEvent::REGISTRATION_FULFILLED => 'auth_registration',
        AuthEvent::PASSKEY_ENROLLED => 'passkey_enrolled',
        AuthEvent::PASSKEY_DELETED => 'passkey_deleted',
        AuthEvent::SESSION_REVOKED => 'session_revoked',
        AuthEvent::SCIM_PROVISIONED => 'scim_provisioned',
        AuthEvent::SCIM_DEPROVISIONED => 'scim_deprovisioned',
    ];

    // Public Methods
    // =========================================================================

    /**
     * Handles one recorded authentication event, mapping it onto a PP event
     * class and landing it on the audit log. Unknown {@see AuthEvent::$name}
     * values are ignored silently (forward-compatibility contract).
     *
     * The neutral `outcome`, subject `userId`, and acting `actorId` pass
     * straight through to `logEvent()`; the emitter handle becomes both the
     * row's `source` column and a `details.source` key. The per-event allowlist
     * in {@see AuditLogService::ALLOWED_DETAILS_BY_EVENT} strips any neutral
     * `details` key not permitted for the mapped class, so passing the emitter's
     * full `details` payload is safe.
     *
     * @param AuthEvent $event the event to handle
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function handle(AuthEvent $event): void
    {
        try {
            $mapped = self::EVENT_MAP[$event->name] ?? null;

            // Unknown neutral name — forward-compatibility no-op. PP's
            // fail-closed registry would drop it anyway, but returning here
            // keeps the drop silent (no stray warning for a name a newer
            // Auth Kit legitimately emits).
            if ($mapped === null) {
                return;
            }

            $details = $event->details;

            // The emitter handle is both the row `source` and a details key —
            // the allowlist lists `source` for every mapped class.
            $details['source'] = $event->emitter;

            // `auth_login` collapses the four `login.*` names; the login method
            // is the neutral name's suffix (`login.magic_link` → `magic_link`).
            if (str_starts_with($event->name, 'login.')) {
                $details['method'] = substr($event->name, strlen('login.'));
            }

            PasswordPolicy::$plugin->getAuditLog()->logEvent(
                userId: $event->userId,
                event: $mapped,
                details: $details,
                outcome: $event->outcome,
                source: $event->emitter,
                changedByUserId: $event->actorId,
            );
        } catch (Throwable $e) {
            // Belt and braces — `Audit::record()` already isolates a throwing
            // sink, and `logEvent()` swallows its own writes, but PP's own
            // defensive style is that a sink never lets an exception escape.
            Craft::error(
                sprintf(
                    'AuthKitAuditSink failed to handle a "%s" event from "%s": %s',
                    $event->name,
                    $event->emitter,
                    $e->getMessage(),
                ),
                'password-policy',
            );
        }
    }
}
