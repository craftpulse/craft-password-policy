<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services\geoip;

/**
 * Class NullGeoIpProvider
 *
 * Null-object {@see GeoIpProviderInterface} — `lookup()` always returns
 * `null`. Bound when no real provider can serve (e.g. a future config
 * that explicitly disables file lookups) so callers never branch on
 * "is a provider present"; they always get the fail-soft `null` the
 * interface contract guarantees.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
final class NullGeoIpProvider implements GeoIpProviderInterface
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function lookup(string $ip): ?GeoResult
    {
        return null;
    }
}
