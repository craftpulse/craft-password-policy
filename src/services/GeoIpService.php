<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\geoip\DbIpFileProvider;
use craftpulse\passwordpolicy\services\geoip\GeoIpProviderInterface;
use craftpulse\passwordpolicy\services\geoip\GeoResult;
use yii\base\Component;

/**
 * Class GeoIpService
 *
 * Single entry point for IP geolocation. Resolves an IP to a country
 * (and, where the bound provider supports it, a region) via a
 * {@see GeoIpProviderInterface}. Production binds {@see DbIpFileProvider}
 * — the bundled, pure-PHP DB-IP Lite country database.
 *
 * **Opt-in, fail-soft.** `lookup()` returns `null` whenever the
 * `geoIpEnabled` setting is off (the GDPR data-minimisation default —
 * geolocation is opt-in), and the underlying provider returns `null` for
 * any unresolvable IP. The service never throws; callers (audit
 * enrichment, the Feature 1 new-device label) treat `null` as "no geo
 * available" and carry on.
 *
 * **Capture vs exposure.** The audit log's `geoCountry` / `geoRegion`
 * columns exist on every edition (`project_audit_capture_principle.md`:
 * capture is universal). This service gates only on the `geoIpEnabled`
 * feature flag — the Enterprise edition gate that actually decides
 * whether enrichment runs lives one layer up, at the
 * `AuditLogService::logEvent()` call site, matching the plugin's
 * "gate exposure, not capture" convention.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GeoIpService extends Component
{
    // Private Properties
    // =========================================================================

    /**
     * @var GeoIpProviderInterface|null memoised provider. Bound lazily on
     *     first use via {@see getProvider()}.
     */
    private ?GeoIpProviderInterface $_provider = null;

    // Public Methods
    // =========================================================================

    /**
     * Returns the bound geolocation provider, binding the default
     * bundled DB-IP file provider on first call.
     *
     * @return GeoIpProviderInterface
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getProvider(): GeoIpProviderInterface
    {
        if ($this->_provider === null) {
            $this->_provider = new DbIpFileProvider();
        }

        return $this->_provider;
    }

    /**
     * Resolves the geolocation of an IP address, or `null` when
     * geolocation is disabled or the IP is unresolvable.
     *
     * The single entry point for every geo consumer — audit enrichment
     * and the Feature 1 new-device label both call this. Returns `null`
     * when:
     *
     *  1. `geoIpEnabled` is off (opt-in default — GDPR data-minimisation).
     *  2. `$ip` is null/empty.
     *  3. The provider could not resolve the IP (private/reserved IP,
     *     unknown IP, missing `.mmdb`, or any internal failure — the
     *     provider contract guarantees `null`, never a throw).
     *
     * @param string|null $ip the raw IP to resolve. Used for the lookup
     *     only — never persisted by this service.
     * @return GeoResult|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function lookup(?string $ip): ?GeoResult
    {
        if (!PasswordPolicy::$plugin->getSettings()->geoIpEnabled) {
            return null;
        }

        if ($ip === null || $ip === '') {
            return null;
        }

        return $this->getProvider()->lookup($ip);
    }

    /**
     * Overrides the bound provider. Test-only seam — production binds the
     * default bundled provider via {@see getProvider()}.
     *
     * @param GeoIpProviderInterface $provider
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function setProvider(GeoIpProviderInterface $provider): void
    {
        $this->_provider = $provider;
    }
}
