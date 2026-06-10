<?php
/**
 * Pest coverage for `DeviceLabelService` — the pure UA→label + IP→mask
 * transforms behind Feature 1 device tracking.
 *
 * Pins:
 *
 *  - `label()` maps the major browser/OS token combinations to a short
 *    "Browser on OS" label, with the specificity ordering that keeps
 *    Edge/Opera/Brave from being mislabelled as Chrome and iOS from being
 *    mislabelled as macOS.
 *  - An unrecognised UA falls back to the "Unknown device" sentinel
 *    rather than leaking the raw string.
 *  - `maskIp()` zeroes the last IPv4 octet, truncates IPv6 to /64, and
 *    returns the "Unknown" sentinel for empty / malformed input.
 *
 * No DB, no edition gate — the service is a pure transform.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\DeviceLabelService;

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getDeviceLabel();
});

// =============================================================================
// label — browser + OS combinations
// =============================================================================

it('labels common user-agent strings as "Browser on OS"', function(string $ua, string $expected) {
    expect($this->service->label($ua))->toBe($expected);
})->with([
    'Chrome on macOS' => [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Chrome on macOS',
    ],
    'Safari on macOS' => [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Safari on macOS',
    ],
    'Safari on iOS (iPhone, not macOS)' => [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'Safari on iOS',
    ],
    'Edge on Windows (not Chrome)' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Edge on Windows',
    ],
    'Firefox on Linux' => [
        'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Firefox on Linux',
    ],
    'Chrome on Android' => [
        'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Chrome on Android',
    ],
    'Opera on Windows (not Chrome)' => [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
        'Opera on Windows',
    ],
]);

// =============================================================================
// label — browser only / OS only / unknown fallback
// =============================================================================

it('returns just the browser when the OS is unknown', function() {
    expect($this->service->label('Firefox/121.0'))->toBe('Firefox');
});

it('returns just the OS when the browser is unknown', function() {
    expect($this->service->label('SomeBot (Windows NT 10.0)'))->toBe('Windows');
});

it('falls back to the unknown-device sentinel for an unrecognised user-agent', function() {
    expect($this->service->label('curl/8.4.0'))->toBe(DeviceLabelService::UNKNOWN_DEVICE_LABEL);
});

it('falls back to the unknown-device sentinel for an empty user-agent', function() {
    expect($this->service->label(''))->toBe(DeviceLabelService::UNKNOWN_DEVICE_LABEL);
});

// =============================================================================
// maskIp — IPv4 zeroes the last octet
// =============================================================================

it('zeroes the last IPv4 octet', function() {
    expect($this->service->maskIp('203.0.113.45'))->toBe('203.0.113.0');
    expect($this->service->maskIp('8.8.8.8'))->toBe('8.8.8.0');
});

// =============================================================================
// maskIp — IPv6 truncates to /64
// =============================================================================

it('truncates IPv6 to its /64 prefix', function() {
    expect($this->service->maskIp('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2::');
});

// =============================================================================
// maskIp — empty / malformed fall back to the sentinel
// =============================================================================

it('returns the unknown sentinel for an empty IP', function() {
    expect($this->service->maskIp(''))->toBe(DeviceLabelService::UNKNOWN_IP);
});

it('returns the unknown sentinel for a malformed IP', function() {
    expect($this->service->maskIp('not-an-ip'))->toBe(DeviceLabelService::UNKNOWN_IP);
});
