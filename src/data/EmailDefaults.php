<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
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
                . "{{ siteName }} account has been broken into — it means the password you are "
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
     * Returns the list of all notification keys this plugin manages, mapped
     * to their default-content factory methods. Used by the install
     * migration and the site propagation listener to seed all keys for a
     * given site.
     *
     * Phase G adds `new-device-alert` and `admin-security-alert` here.
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
        ];
    }
}
