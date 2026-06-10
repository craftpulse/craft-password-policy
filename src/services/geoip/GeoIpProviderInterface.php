<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services\geoip;

/**
 * Interface GeoIpProviderInterface
 *
 * The provider seam behind {@see \craftpulse\passwordpolicy\services\GeoIpService}.
 * Decoupled so tests can swap a fake in without touching the bundled
 * `.mmdb`, and so a future operator-managed MaxMind database or external
 * API can bind a different implementation without the service or its
 * callers changing.
 *
 * **Total — never throws.** A provider MUST return `null` for any
 * unresolvable input: missing/unreadable database, unknown IP, private
 * or reserved IP, malformed IP, or any internal `\Throwable`. The geo
 * surface is strictly best-effort enrichment layered on top of login +
 * audit; it must never propagate an exception into those paths. The
 * fail-soft contract lives here so every implementation honours it.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
interface GeoIpProviderInterface
{
    // Public Methods
    // =========================================================================

    /**
     * Resolves the geolocation of an IP address.
     *
     * Returns `null` for any unresolvable input — see the interface
     * docblock's "Total — never throws" contract. Implementations must
     * swallow every `\Throwable` internally and return `null`; a thrown
     * exception is a contract violation.
     *
     * @param string $ip the raw IP address to resolve
     * @return GeoResult|null the resolved geolocation, or null when
     *     unresolvable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function lookup(string $ip): ?GeoResult;
}
