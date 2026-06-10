<?php
/**
 * Pest coverage for `GeoIpService` — the IP geolocation entry point.
 *
 * Pins the fail-soft + opt-in contract:
 *
 *  - Disabled (`geoIpEnabled` off) → `lookup()` returns null regardless
 *    of IP. Opt-in is the GDPR data-minimisation default.
 *  - Null / empty IP → null.
 *  - Private / loopback / reserved IP → null (no public geolocation).
 *  - A known public IP → a `GeoResult` with a country code, read from the
 *    bundled DB-IP Lite database. Skipped gracefully when the `.mmdb` is
 *    absent from the checkout so the null/disabled contract still gates.
 *  - A custom provider can be injected (the test seam) and a missing
 *    database file degrades to null without throwing.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\geoip\DbIpFileProvider;
use craftpulse\passwordpolicy\services\geoip\GeoResult;

// =============================================================================
// Setup — restore the geoIpEnabled flag + provider after every test
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getGeoIp();
    $this->originalGeoIpEnabled = $this->plugin->getSettings()->geoIpEnabled;
});

afterEach(function() {
    $this->plugin->getSettings()->geoIpEnabled = $this->originalGeoIpEnabled;
    // Reset the memoised provider so the next test gets the default
    // bundled provider rather than a fake one this test injected.
    $this->service->setProvider(new DbIpFileProvider());
});

// =============================================================================
// Disabled — opt-in default returns null for everything
// =============================================================================

it('returns null when geoIpEnabled is off', function() {
    $this->plugin->getSettings()->geoIpEnabled = false;

    expect($this->service->lookup('8.8.8.8'))->toBeNull();
});

// =============================================================================
// Null / empty IP
// =============================================================================

it('returns null for a null IP even when enabled', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;

    expect($this->service->lookup(null))->toBeNull();
});

it('returns null for an empty IP even when enabled', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;

    expect($this->service->lookup(''))->toBeNull();
});

// =============================================================================
// Private / reserved / malformed IPs — no public geolocation
// =============================================================================

it('returns null for a loopback IP', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;

    expect($this->service->lookup('127.0.0.1'))->toBeNull();
});

it('returns null for an RFC 1918 private IP', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;

    expect($this->service->lookup('192.168.1.42'))->toBeNull();
    expect($this->service->lookup('10.0.0.1'))->toBeNull();
});

it('returns null for a malformed IP', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;

    expect($this->service->lookup('not-an-ip'))->toBeNull();
});

// =============================================================================
// Known public IP — resolves via the bundled DB-IP Lite database
// =============================================================================

it('resolves a known public IP to a country code via the bundled database', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;

    $result = $this->service->lookup('8.8.8.8');

    expect($result)->toBeInstanceOf(GeoResult::class);
    expect($result->countryCode)->toBeString();
    expect($result->countryCode)->not->toBe('');
    expect(strlen($result->countryCode))->toBe(2);
})->skip(
    fn() => !is_file(
        dirname(__DIR__, 3) . '/src/data/geoip/dbip-country-lite.mmdb',
    ),
    'Bundled DB-IP Lite .mmdb is not present in this checkout.',
);

// =============================================================================
// Missing database file — provider degrades to null without throwing
// =============================================================================

it('returns null without throwing when the database file is missing', function() {
    $this->plugin->getSettings()->geoIpEnabled = true;
    $this->service->setProvider(
        new DbIpFileProvider('/nonexistent/path/does-not-exist.mmdb'),
    );

    expect($this->service->lookup('8.8.8.8'))->toBeNull();
});

// =============================================================================
// DbIpFileProvider in isolation — never throws on bad input
// =============================================================================

it('the DbIpFileProvider returns null for a private IP without opening the reader', function() {
    $provider = new DbIpFileProvider('/nonexistent/path/does-not-exist.mmdb');

    // Private IP short-circuits before the reader is ever touched, so a
    // missing database is irrelevant here — still null, still no throw.
    expect($provider->lookup('192.168.0.1'))->toBeNull();
});
