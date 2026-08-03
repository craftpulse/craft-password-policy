<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use yii\base\Component;

/**
 * Class DeviceLabelService
 *
 * Two pure, dependency-free transforms used by Feature 1 device tracking:
 *
 *  - {@see label()} turns a raw user-agent string into a short
 *    human-readable label ("Chrome on macOS"). A deliberately small
 *    `str_contains` heuristic — device IDENTITY is the SHA-256 fingerprint
 *    {@see DeviceTrackingService} computes, not this label, so a precise
 *    UA parse (and the composer dependency it would require) buys nothing.
 *    The label is display sugar for the new-device alert email + the
 *    stored row.
 *
 *  - {@see maskIp()} reduces an IP to the privacy-minimised form the
 *    plugin persists everywhere a network address surfaces: IPv4 with the
 *    last octet zeroed (`203.0.113.0`), IPv6 truncated to its /64 prefix
 *    (`2001:db8:1:2::`). The raw IP is NEVER stored — only this masked
 *    form lands on a device row or in an alert email (see `security.md`).
 *
 * Both methods are total — they never throw, and they degrade to a safe
 * sentinel ("Unknown device" / "Unknown") on unparseable input rather than
 * leaking the raw value.
 *
 * Edition: universal. The service is pure transform with no edition gate;
 * the alert email that consumes the label is Enterprise-gated one layer up.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class DeviceLabelService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Fallback label when the user-agent is empty or matches no known
     * browser/OS token.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const UNKNOWN_DEVICE_LABEL = 'Unknown device';

    /**
     * Fallback masked-IP value when the IP is empty or unparseable.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const UNKNOWN_IP = 'Unknown';

    // Public Methods
    // =========================================================================

    /**
     * Returns a short human-readable label for a user-agent string, e.g.
     * "Chrome on macOS", "Safari on iOS", or "Firefox" when the OS is
     * not recognised. Returns {@see UNKNOWN_DEVICE_LABEL} when neither a
     * browser nor an OS token matches.
     *
     * The match order matters: more specific tokens are tested before
     * the families they are built on (Edge/Opera/Brave before Chrome,
     * because they all carry "Chrome" in their UA; iOS before macOS,
     * because iPad/iPhone UAs also mention "Mac OS X").
     *
     * @param string $userAgent the raw request user-agent
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function label(string $userAgent): string
    {
        $browser = $this->_browser($userAgent);
        $os = $this->_os($userAgent);

        if ($browser === null && $os === null) {
            return self::UNKNOWN_DEVICE_LABEL;
        }

        if ($browser !== null && $os !== null) {
            return "{$browser} on {$os}";
        }

        // Exactly one of the two is non-null here (the both-null case
        // returned above). `??` resolves to whichever it is.
        return $browser ?? $os;
    }

    /**
     * Masks an IP address to the privacy-minimised form the plugin
     * persists: IPv4 with the last octet zeroed, IPv6 truncated to its
     * /64 prefix. Returns {@see UNKNOWN_IP} for an empty or unparseable
     * address.
     *
     * @param string $ip the raw IP address
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function maskIp(string $ip): string
    {
        if ($ip === '') {
            return self::UNKNOWN_IP;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $octets = explode('.', $ip);
            $octets[3] = '0';

            return implode('.', $octets);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $this->_maskIpv6($ip);
        }

        return self::UNKNOWN_IP;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the browser name for a user-agent, or null when none of the
     * known tokens match.
     *
     * @param string $userAgent
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _browser(string $userAgent): ?string
    {
        return match (true) {
            str_contains($userAgent, 'Edg') => 'Edge',
            str_contains($userAgent, 'OPR'), str_contains($userAgent, 'Opera') => 'Opera',
            str_contains($userAgent, 'Brave') => 'Brave',
            str_contains($userAgent, 'SamsungBrowser') => 'Samsung Internet',
            str_contains($userAgent, 'Firefox') => 'Firefox',
            str_contains($userAgent, 'Chrome') || str_contains($userAgent, 'CriOS') => 'Chrome',
            // Safari must come after Chrome — Chrome UAs also contain
            // "Safari" for WebKit compatibility.
            str_contains($userAgent, 'Safari') => 'Safari',
            default => null,
        };
    }

    /**
     * Truncates an IPv6 address to its /64 prefix in compressed form
     * (e.g. `2001:db8:1:2:3:4:5:6` → `2001:db8:1:2::`). Uses
     * `inet_pton`/`inet_ntop` so the output is always a valid, normalised
     * address.
     *
     * @param string $ip a validated IPv6 address
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _maskIpv6(string $ip): string
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return self::UNKNOWN_IP;
        }

        // Keep the first 64 bits (8 bytes), zero the rest.
        $masked = substr($packed, 0, 8) . str_repeat("\0", 8);
        $result = @inet_ntop($masked);

        return $result !== false ? $result : self::UNKNOWN_IP;
    }

    /**
     * Returns the operating-system name for a user-agent, or null when
     * none of the known tokens match.
     *
     * @param string $userAgent
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _os(string $userAgent): ?string
    {
        return match (true) {
            // iOS must precede macOS — iPad/iPhone UAs mention "Mac OS X".
            str_contains($userAgent, 'iPhone'), str_contains($userAgent, 'iPad'), str_contains($userAgent, 'iPod') => 'iOS',
            str_contains($userAgent, 'Android') => 'Android',
            str_contains($userAgent, 'Windows') => 'Windows',
            str_contains($userAgent, 'Mac OS X'), str_contains($userAgent, 'Macintosh') => 'macOS',
            str_contains($userAgent, 'CrOS') => 'ChromeOS',
            str_contains($userAgent, 'Linux') => 'Linux',
            default => null,
        };
    }
}
