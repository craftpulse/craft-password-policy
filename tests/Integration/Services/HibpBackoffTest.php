<?php
/**
 * Pest coverage for `PasswordService::hibp()` and the consumer-side 429
 * backoff short-circuit. Mocks the underlying `HibpClientInterface` via
 * `HibpClientFake` so no live HIBP calls happen — the fake's
 * `$queryCalls` counter is the regression-vector pin: any future refactor
 * that reorders the early-return suddenly sees `query()` called when the
 * backoff is supposed to suppress the lookup.
 *
 * The Guzzle-level 429-parsing tests live in `GuzzleHibpClientTest` —
 * this file scopes to "what does PasswordService do when the client
 * reports the backoff is active" + the breach/clean/null result mapping.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\HibpClientInterface;
use craftpulse\passwordpolicy\tests\Support\HibpClientFake;

// =============================================================================
// Setup — swap the real Guzzle-backed client for the in-memory fake
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;

    // Stash the original client reference so afterEach can restore it.
    // The plugin's DI container resolves the binding lazily — calling
    // `getHibpClient()` here both warms the cached instance AND gives us
    // the live object to put back when the test finishes.
    $this->originalClient = $this->plugin->getHibpClient();

    $this->fake = new HibpClientFake();
    $this->plugin->set('hibpClient', $this->fake);
});

afterEach(function() {
    $this->plugin->set('hibpClient', $this->originalClient);
});

// =============================================================================
// PasswordService::hibp() — happy path and result mapping
// =============================================================================

it('returns true when the suffix appears in the response body', function() {
    $hash = strtoupper(sha1('correct horse battery staple'));

    $this->fake->setBreachedHash($hash);

    $result = $this->plugin->getPasswords()->hibp('correct horse battery staple');

    expect($result)->toBeTrue()
        ->and($this->fake->queryCalls)->toBe(1);
});

it('returns false when the suffix is absent from the response body', function() {
    $this->fake->setCleanResponse();

    $result = $this->plugin->getPasswords()->hibp('this-password-is-not-in-the-response');

    expect($result)->toBeFalse()
        ->and($this->fake->queryCalls)->toBe(1);
});

it('returns null when the client reports the API is unreachable', function() {
    // Fail-open contract: client returns null → service returns null →
    // caller can distinguish "unable to check" from "not breached".
    $this->fake->nextResponse = null;

    $result = $this->plugin->getPasswords()->hibp('whatever');

    expect($result)->toBeNull()
        ->and($this->fake->queryCalls)->toBe(1);
});

it('sends only the 5-char uppercase SHA-1 prefix to the client', function() {
    // k-anonymity contract: only the prefix leaves the consumer. Hash is
    // computed inline; every call should produce a 5-char uppercase hex
    // prefix, never the full hash, never the plaintext.
    $this->fake->setCleanResponse();

    $this->plugin->getPasswords()->hibp('correct horse battery staple');

    $expectedPrefix = strtoupper(substr(sha1('correct horse battery staple'), 0, 5));

    expect($this->fake->queryPrefixes)->toBe([$expectedPrefix])
        ->and($this->fake->queryPrefixes[0])->toMatch('/^[0-9A-F]{5}$/');
});

// =============================================================================
// PasswordService::hibp() — backoff short-circuit (the regression vector)
// =============================================================================

it('short-circuits to null when the client reports backoff active', function() {
    // The critical regression vector — if a future refactor reorders the
    // early-return, every login during a backoff window calls the API.
    $this->fake->backoffActive = true;
    $this->fake->setCleanResponse(); // would be a "clean" body if asked

    $result = $this->plugin->getPasswords()->hibp('whatever');

    expect($result)->toBeNull()
        ->and($this->fake->queryCalls)->toBe(0);
});

// =============================================================================
// PasswordService::isHibpBackoffActive() — passthrough
// =============================================================================

it('proxies isHibpBackoffActive() through to the client when inactive', function() {
    $this->fake->backoffActive = false;

    expect($this->plugin->getPasswords()->isHibpBackoffActive())->toBeFalse();
});

it('proxies isHibpBackoffActive() through to the client when active', function() {
    $this->fake->backoffActive = true;

    expect($this->plugin->getPasswords()->isHibpBackoffActive())->toBeTrue();
});

// =============================================================================
// Listener-shaped flow — the HIBP-on-login path also short-circuits on backoff
// =============================================================================

it('does not call query() when the listener-shaped consumer sees backoff active', function() {
    // Mirror the gate used at PasswordPolicy::_runHibpOnLoginCheck() —
    // a separate `isHibpBackoffActive()` check ahead of the main hibp()
    // call so the listener can short-circuit before even building a
    // dedup cache key. Both gates point at the same client and must
    // agree on the answer.
    $this->fake->backoffActive = true;

    $service = $this->plugin->getPasswords();

    // Consumer-shaped guard:
    if ($service->isHibpBackoffActive()) {
        // listener returns early — no API call
        expect($this->fake->queryCalls)->toBe(0);
        return;
    }

    // Defensive — should never reach here in this test
    $service->hibp('something');
    throw new \RuntimeException('listener gate did not short-circuit');
});

// =============================================================================
// DI wiring — ServicesTrait registers the interface, not the concrete class
// =============================================================================

it('binds the hibpClient as a HibpClientInterface implementation', function() {
    expect($this->plugin->getHibpClient())->toBeInstanceOf(HibpClientInterface::class);
});
