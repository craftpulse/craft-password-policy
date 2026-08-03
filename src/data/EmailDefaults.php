<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\data;

/**
 * Class EmailDefaults
 *
 * Static defaults for the per-site notification template seed rows. Each
 * notification key has a corresponding factory method returning the default
 * `content` JSON shape (`subject`, `body`, optional sender overrides).
 *
 * Defaults are intentionally plaintext-only and reference Twig tokens
 * (`{{ user }}`, `{{ daysUntilExpiry }}`, `{{ siteName }}`) that the
 * NotificationTemplateService renders against per-user context at send time.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class EmailDefaults
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the default content shape for the `expiry-reminder` notification.
     *
     * Sender override fields default to null — the service falls back to
     * Craft's system mailer defaults (`email.fromName` / `email.fromEmail`)
     * when no override is set on the template row.
     *
     * @return array<string, string|null>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function expiryReminder(): array
    {
        return [
            'subject' => 'Your {{ siteName }} password expires in {{ daysUntilExpiry }} days',
            'body' => "Hi {{ user.friendlyName ?? user.username }},\n\n"
                . "Your {{ siteName }} password will expire in {{ daysUntilExpiry }} days. "
                . "Please sign in and update it before then to avoid losing access to your account.\n\n"
                . "If you did not request this reminder, you can safely ignore this email.\n\n"
                . "Thanks,\n"
                . "The {{ siteName }} team",
            'senderName' => null,
            'senderEmail' => null,
            'replyTo' => null,
        ];
    }

    /**
     * Returns the default content shape for the `breach-detected` notification.
     *
     * Sent when HIBP-on-login (Pro) detects that a user's password appears in
     * the Pwned Passwords breach database. The plugin sets
     * `passwordResetRequired = true` on the same login so the user is forced
     * to choose a new password on their next sign-in.
     *
     * @return array<string, string|null>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function breachDetected(): array
    {
        return [
            'subject' => 'Action required: your {{ siteName }} password was found in a public breach',
            'body' => "Hi {{ user.friendlyName ?? user.username }},\n\n"
                . "We checked your password against the Have I Been Pwned breach database "
                . "during your most recent sign-in and found a match. This does NOT mean your "
                . "{{ siteName }} account has been broken into. It means the password you are "
                . "using has appeared in a public data breach somewhere on the internet, and "
                . "automated attackers regularly try those exact passwords against every site.\n\n"
                . "What we have already done:\n"
                . "  • Marked your account as requiring a password reset on your next sign-in.\n\n"
                . "What you should do:\n"
                . "  • Choose a new, unique password for {{ siteName }}.\n"
                . "  • If you reuse this password anywhere else, change it there too.\n\n"
                . "Detected at: {{ detectedAt|datetime }}\n\n"
                . "Thanks,\n"
                . "The {{ siteName }} team",
            'senderName' => null,
            'senderEmail' => null,
            'replyTo' => null,
        ];
    }

    /**
     * Returns the default content shape for the `new-device-alert` notification.
     *
     * Sent when HIBP-on-login (Pro) detects a sign-in from a previously
     * unseen device fingerprint. `deviceLabel` is a free-form description
     * (e.g. `"Chrome on macOS"`) and `maskedIp` is the source IP with the
     * last octet redacted for privacy. Both are populated by the new-
     * device detection listener before dispatch.
     *
     * @return array<string, string|null>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function newDeviceAlert(): array
    {
        return [
            'subject' => 'New sign-in to your {{ siteName }} account',
            'body' => "Hi {{ user.friendlyName ?? user.username }},\n\n"
                . "We detected a new sign-in to your {{ siteName }} account from a device "
                . "we have not seen before.\n\n"
                . "Device: {{ deviceLabel }}\n"
                . "IP address: {{ maskedIp }}\n\n"
                . "If this was you, no further action is needed, as this email is for awareness only.\n\n"
                . "If this was NOT you:\n"
                . "  - Change your password immediately.\n"
                . "  - Review any other sessions on your account.\n"
                . "  - Contact a site administrator if you suspect your account has been compromised.\n\n"
                . "Thanks,\n"
                . "The {{ siteName }} team",
            'senderName' => null,
            'senderEmail' => null,
            'replyTo' => null,
        ];
    }

    /**
     * Returns the default content shape for the `inactive-account` notification.
     *
     * Sent by the Feature 5 scan (Pro) in `notify` mode to a user whose
     * account has been dormant past the configured inactivity threshold.
     * Awareness-only — the email asks the user to sign in to keep their
     * account active; it does NOT itself suspend anything (that is the
     * separate `suspend` action mode).
     *
     * @return array<string, string|null>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function inactiveAccount(): array
    {
        return [
            'subject' => 'Your {{ siteName }} account has been inactive',
            'body' => "Hi {{ user.friendlyName ?? user.username }},\n\n"
                . "We noticed you have not signed in to your {{ siteName }} account for a while. "
                . "For security, accounts that stay inactive may be suspended.\n\n"
                . "To keep your account active, simply sign in:\n\n"
                . "  - Visit {{ siteName }} and log in as usual.\n\n"
                . "If you no longer need this account, you can ignore this email and it may be "
                . "suspended in line with our security policy.\n\n"
                . "Thanks,\n"
                . "The {{ siteName }} team",
            'senderName' => null,
            'senderEmail' => null,
            'replyTo' => null,
        ];
    }

    /**
     * Returns the default content shape for the `admin-security-alert` notification.
     *
     * Sent to the configured `adminAlertEmail` recipient on security
     * events the operator opted into via `adminAlertEvents`. The
     * `event` token is the machine key (e.g. `breach_detected`,
     * `lockout`); `context` is a free-form `array<string, mixed>` of
     * event-specific metadata (e.g. `{ userId: 7, email: '...' }`).
     *
     * Admin-recipient templates do NOT receive a `user` Twig variable —
     * the recipient is the operator, not an end-user — so the default
     * body avoids `{{ user.* }}` references.
     *
     * @return array<string, string|null>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function adminSecurityAlert(): array
    {
        return [
            'subject' => '[{{ siteName }}] Security alert: {{ event }}',
            'body' => "A security event was recorded on {{ siteName }}.\n\n"
                . "Event: {{ event }}\n"
                . "{% if context|length %}"
                . "Context:\n"
                . "{% for key, value in context %}"
                . "  - {{ key }}: {{ value is iterable ? value|join(', ') : value }}\n"
                . "{% endfor %}"
                . "{% endif %}\n"
                . "Review the password-policy audit log or notifications activity surface "
                . "in the control panel for more detail.\n\n"
                . "This message was sent because the event matches your `adminAlertEvents` "
                . "configuration. To stop receiving these emails, remove the event from "
                . "that list or clear `adminAlertEmail` entirely.",
            'senderName' => null,
            'senderEmail' => null,
            'replyTo' => null,
        ];
    }

    /**
     * Returns the list of all notification keys this plugin manages, mapped
     * to their default-content factory methods. Used by the install
     * migration and the site propagation listener to seed all keys for a
     * given site.
     *
     * @return array<string, callable(): array<string, string|null>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function all(): array
    {
        return [
            'expiry-reminder' => [self::class, 'expiryReminder'],
            'breach-detected' => [self::class, 'breachDetected'],
            'new-device-alert' => [self::class, 'newDeviceAlert'],
            'inactive-account' => [self::class, 'inactiveAccount'],
            'admin-security-alert' => [self::class, 'adminSecurityAlert'],
        ];
    }
}
