<?php
/**
 * Pest coverage for `SecurityService` — the plugin's cross-cutting security
 * primitives.
 *
 * Pins three contracts:
 *
 *  - `canManageUserCredentials()` is the single peer-admin gate every
 *    admin-on-user credential write clears first. Asserted here as a predicate
 *    rather than only through the four surfaces that call it (the Password
 *    Security pane's Actions flag, the force-reset POST handler, the
 *    `ForcePasswordReset` bulk element action, and the direct password-set
 *    handler on `UserPasswordController`), because a duplicated authorization
 *    check drifts and the copy that drifts is the one nobody tests.
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
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// canManageUserCredentials() — the one shared peer-admin gate
// =============================================================================

it('refuses a non-admin actor aiming at an admin target', function() {
    // The escalation the gate closes. Both `pp:user-force-reset` and
    // `pp:change-user-passwords` are grantable to non-admins, so neither
    // permission may carry "replace an administrator's password" or "lock an
    // administrator out of their own account" with it.
    $actor = UserFactory::nonAdmin();
    $target = UserFactory::admin();

    expect(PasswordPolicy::$plugin->getSecurity()->canManageUserCredentials($target, $actor))
        ->toBeFalse();
});

it('allows a non-admin actor aiming at a non-admin target', function() {
    $actor = UserFactory::nonAdmin();
    $target = UserFactory::nonAdmin();

    expect(PasswordPolicy::$plugin->getSecurity()->canManageUserCredentials($target, $actor))
        ->toBeTrue();
});

it('allows an admin actor aiming at an admin target', function() {
    // Co-administrators are peers and Craft already treats them as mutually
    // trusted, so the gate is about crossing a privilege boundary rather than
    // about admin accounts being untouchable.
    $actor = UserFactory::admin();
    $target = UserFactory::admin();

    expect(PasswordPolicy::$plugin->getSecurity()->canManageUserCredentials($target, $actor))
        ->toBeTrue();
});

it('refuses when there is no identified actor', function() {
    $target = UserFactory::nonAdmin();

    expect(PasswordPolicy::$plugin->getSecurity()->canManageUserCredentials($target, null))
        ->toBeFalse();
});

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
