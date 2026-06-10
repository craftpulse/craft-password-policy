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

use GeoIp2\Database\Reader;
use Throwable;

/**
 * Class DbIpFileProvider
 *
 * Country-level {@see GeoIpProviderInterface} backed by the bundled
 * DB-IP Lite MaxMind-format database (`src/data/geoip/dbip-country-
 * lite.mmdb`), read through the pure-PHP `geoip2/geoip2` library. No
 * PECL extension, no operator download, no external API.
 *
 * IP Geolocation by DB-IP (https://db-ip.com). The bundled database is
 * the DB-IP IP-to-Country Lite database, licensed under Creative Commons
 * Attribution 4.0 International (CC BY 4.0). The attribution above is the
 * required notice; see `src/data/geoip/README.md` for the licence detail
 * and the refresh procedure.
 *
 * **Fail-soft everywhere.** `lookup()` returns `null` — never throws —
 * for: a missing or unreadable `.mmdb` (the binary ships in the repo but
 * a partial checkout / `.gitattributes export-ignore` could drop it), a
 * private or reserved IP (RFC 1918, loopback, link-local — no public
 * geolocation exists and feeding them to the reader wastes a lookup), a
 * malformed IP, an IP the database does not know, or any internal
 * `\Throwable` from the reader. The geo surface is best-effort
 * enrichment on top of login + audit; it must never break those paths.
 *
 * The `Reader` is opened lazily on first `lookup()` and memoised — the
 * `.mmdb` is mmap-backed, so a single open per request is cheap and
 * repeated lookups (e.g. an audit write plus a new-device label in the
 * same request) reuse it.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
final class DbIpFileProvider implements GeoIpProviderInterface
{
    // Private Properties
    // =========================================================================

    /**
     * @var string absolute path to the bundled DB-IP Lite `.mmdb`.
     */
    private string $_databasePath;

    /**
     * @var Reader|null memoised reader handle. Stays null when the file
     *     is missing/unreadable or the open threw — `lookup()` then
     *     returns null without re-attempting the open every call.
     */
    private ?Reader $_reader = null;

    /**
     * @var bool whether an open has already been attempted. Distinguishes
     *     "not yet opened" from "opened and failed, don't retry".
     */
    private bool $_openAttempted = false;

    // Public Methods
    // =========================================================================

    /**
     * @param string|null $databasePath absolute path to the `.mmdb`.
     *     Defaults to the bundled DB-IP Lite country database.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(?string $databasePath = null)
    {
        $this->_databasePath = $databasePath
            ?? dirname(__DIR__, 2) . '/data/geoip/dbip-country-lite.mmdb';
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function lookup(string $ip): ?GeoResult
    {
        // Private / reserved / malformed IPs have no public geolocation.
        // Reject them before touching the reader — both a micro-
        // optimisation and a guard against the reader throwing
        // AddressNotFoundException on every loopback hit in a dev env.
        if (!$this->_isPublicIp($ip)) {
            return null;
        }

        $reader = $this->_getReader();

        if ($reader === null) {
            return null;
        }

        try {
            $record = $reader->country($ip);

            return new GeoResult(
                country: $record->country->name,
                countryCode: $record->country->isoCode,
                region: null,
            );
        } catch (Throwable) {
            // AddressNotFoundException (unknown IP), InvalidDatabaseException
            // (corrupt .mmdb mid-read), or anything else — fail soft.
            return null;
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the memoised reader, opening it on first call. Returns
     * `null` (and memoises that failure) when the file is missing,
     * unreadable, or the open threw.
     *
     * @return Reader|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getReader(): ?Reader
    {
        if ($this->_openAttempted) {
            return $this->_reader;
        }

        $this->_openAttempted = true;

        if (!is_file($this->_databasePath) || !is_readable($this->_databasePath)) {
            return null;
        }

        try {
            $this->_reader = new Reader($this->_databasePath);
        } catch (Throwable) {
            $this->_reader = null;
        }

        return $this->_reader;
    }

    /**
     * Returns whether the given string is a syntactically valid public
     * IP (v4 or v6) — i.e. not private (RFC 1918), not reserved
     * (loopback, link-local), and not malformed.
     *
     * @param string $ip
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _isPublicIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }
}
