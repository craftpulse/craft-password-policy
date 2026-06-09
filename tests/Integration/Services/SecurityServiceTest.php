<?php
/**
 * Pest coverage for `SecurityService` — the plugin's CSP-nonce source.
 *
 * Pins two contracts:
 *
 *  - `getNonce()` returns a stable, non-empty per-request nonce. The plugin
 *    hands this to the indicator script's asset registration when `cspNonce`
 *    is enabled, so it must be memoized (same value across calls within a
 *    request) and long enough to be unguessable.
 *  - The dead `applyCsp()` method (which emitted an `unsafe-inline` CSP
 *    header and was never wired into any request path) stays removed. The
 *    plugin only nonce-tags its OWN scripts; it does not emit a site-wide
 *    Content-Security-Policy header — operators own their CSP. Reintroducing
 *    `applyCsp()` would silently hand an `unsafe-inline` policy to anyone who
 *    called it, defeating the nonce.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\SecurityService;

// =============================================================================
// getNonce()
// =============================================================================

it('returns a non-empty nonce', function() {
    $nonce = PasswordPolicy::$plugin->getSecurity()->getNonce();

    expect($nonce)->toBeString();
    expect($nonce)->not->toBe('');
    expect(strlen($nonce))->toBeGreaterThanOrEqual(32);
});

it('memoizes the nonce across calls within a request', function() {
    $service = PasswordPolicy::$plugin->getSecurity();

    expect($service->getNonce())->toBe($service->getNonce());
});

// =============================================================================
// applyCsp() removal — dead unsafe-inline emitter must stay gone
// =============================================================================

it('does not expose a CSP-header emitter (the unsafe-inline applyCsp is removed)', function() {
    expect(method_exists(SecurityService::class, 'applyCsp'))->toBeFalse();
});
