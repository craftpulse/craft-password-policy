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
 * Class GeoResult
 *
 * Immutable value object describing the geolocation of an IP address.
 * Every field is nullable — the bundled DB-IP Lite database is country-
 * level, so `region` is almost always `null`, and a lookup that resolves
 * the IP but not the country (rare, but possible for anycast / reserved
 * ranges) still returns a `GeoResult` with `null` members rather than a
 * bare `null`. Callers that only care about "did we resolve anything"
 * test the individual members.
 *
 * The plugin only ever PERSISTS `countryCode` + `region` (see
 * `AuditLogService::logEvent()`); the human-readable `country` name is
 * carried for display surfaces (the Feature 1 new-device label) that
 * want "United States" rather than "US". The raw IP is never stored —
 * it stays in request scope, is fed to the provider, and is discarded.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
final class GeoResult
{
    // Public Properties
    // =========================================================================

    /**
     * @var string|null the human-readable country name (e.g. "United
     *     States"), or null when the database could not resolve it.
     */
    public readonly ?string $country;

    /**
     * @var string|null the ISO 3166-1 alpha-2 country code (e.g. "US"),
     *     or null when the database could not resolve it. This is the
     *     value persisted to the audit log's `geoCountry` column.
     */
    public readonly ?string $countryCode;

    /**
     * @var string|null the subdivision / region name, or null. The
     *     bundled DB-IP Lite database is country-level, so this is
     *     almost always null; the field exists so a future city-level
     *     database can populate it without a value-object change.
     */
    public readonly ?string $region;

    // Public Methods
    // =========================================================================

    /**
     * @param string|null $country
     * @param string|null $countryCode
     * @param string|null $region
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        ?string $country = null,
        ?string $countryCode = null,
        ?string $region = null,
    ) {
        $this->country = $country;
        $this->countryCode = $countryCode;
        $this->region = $region;
    }
}
