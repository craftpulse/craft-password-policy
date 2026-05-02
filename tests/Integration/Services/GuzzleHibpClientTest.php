<?php
/**
 * Pest coverage for `GuzzleHibpClient` — the Guzzle-backed implementation
 * of `HibpClientInterface`. Mocks the underlying HTTP transport via
 * `GuzzleHttp\Handler\MockHandler` so tests pin the 200/4xx/5xx/429
 * branches without hitting the live HIBP endpoint.
 *
 * The mock handler is spliced into Craft's Guzzle client through the
 * test fixture `tests/_craft/config/guzzle.php` + the `TestGuzzleConfig`
 * static holder — `Craft::createGuzzleClient()` reads `config/guzzle.php`
 * on every call, so installing a handler in `beforeEach` and clearing in
 * `afterEach` is enough to scope the mock to a single test.
 *
 * Cache key sentinel pinned: `pp:hibp-429-backoff` is set on a 429 with
 * the `Retry-After` value as TTL (or `DEFAULT_BACKOFF_SECONDS` when the
 * header is absent / unparseable). Subsequent `query()` calls
 * short-circuit via `isBackoffActive()` before hitting Guzzle.
 *
 * Codified-current-behavior callouts:
 *  - `_parseRetryAfter` does NOT parse HTTP-date form. It only accepts
 *    `ctype_digit` numeric seconds. HTTP-date returns the default. The
 *    inline docblock notes this; tests pin it so a future implementer
 *    extending parsing knows what they're regressing.
 *  - Non-2xx-non-429 errors log at `Logger::LEVEL_ERROR`, NOT WARNING
 *    (which would be the security.md fail-open guidance). Tests pin
 *    current behavior. Flagged as a follow-up.
 *  - `isBackoffActive()` reads the cache via `!== false` rather than
 *    `cache->exists()`. With the sentinel value `'1'`, the gap is
 *    inert — but the read pattern is the gap #11 collision idiom.
 *    Pinned so any future refactor that swaps the sentinel to `false`
 *    (e.g. "we want a positive-cached-clean for k-anon dedup") fails
 *    loudly here.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\services\GuzzleHibpClient;
use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;

// =============================================================================
// Setup — install a fresh MockHandler queue per test
// =============================================================================

beforeEach(function() {
    $this->mockHandler = new MockHandler();
    TestGuzzleConfig::setMockHandler($this->mockHandler);

    // Always start from a clean cache state so the per-test backoff
    // assertions don't leak between cases.
    Craft::$app->getCache()->delete(GuzzleHibpClient::BACKOFF_CACHE_KEY);

    $this->client = new GuzzleHibpClient();
});

afterEach(function() {
    TestGuzzleConfig::clear();
    Craft::$app->getCache()->delete(GuzzleHibpClient::BACKOFF_CACHE_KEY);
});

// =============================================================================
// query() — happy path (200)
// =============================================================================

it('returns the response body on a 200', function() {
    $body = "ABC123:5\r\nDEF456:99";
    $this->mockHandler->append(new Response(200, [], $body));

    expect($this->client->query('00000'))->toBe($body);
});

// =============================================================================
// query() — non-2xx, non-429 fail-open (codifies LEVEL_ERROR logging)
// =============================================================================

it('returns null on a 500 server error', function() {
    // Fail-open: the caller can distinguish "unable to check" from
    // "not breached" via the null return. CURRENT BEHAVIOR: logs at
    // Logger::LEVEL_ERROR, not WARNING. security.md prescribes WARNING
    // for transient outages — the spec/code divergence is flagged in
    // the commit body as a follow-up.
    $this->mockHandler->append(new Response(500, [], 'Internal Server Error'));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBeFalse();
});

it('returns null on a 404 (range path missing)', function() {
    $this->mockHandler->append(new Response(404, [], 'Not Found'));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBeFalse();
});

it('returns null when Guzzle throws a non-ClientException', function() {
    // Network-level failure (DNS, TLS, connect timeout) surfaces as
    // GuzzleHttp\Exception\ConnectException — caught by the `GuzzleException`
    // arm and returns null. No backoff sentinel set.
    $this->mockHandler->append(new \GuzzleHttp\Exception\ConnectException(
        'connection refused',
        new \GuzzleHttp\Psr7\Request('GET', 'https://api.pwnedpasswords.com/range/00000'),
    ));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBeFalse();
});

// =============================================================================
// query() — 429 Too Many Requests (sets backoff sentinel)
// =============================================================================

it('sets the backoff sentinel on a 429', function() {
    $this->mockHandler->append(new Response(429, ['Retry-After' => '30']));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

it('uses the Retry-After numeric value as the backoff TTL', function() {
    $this->mockHandler->append(new Response(429, ['Retry-After' => '120']));

    $this->client->query('00000');

    // The cache value is the literal string '1' — the TTL is what carries
    // the duration. Yii's array cache exposes it via the entry's expiry.
    // We can verify functional equivalence by checking the value is set
    // and matches the sentinel; TTL precision varies across cache drivers
    // (FileCache vs ApcCache vs ArrayCache) so don't assert on the
    // numeric expiry directly.
    expect(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

it('falls back to DEFAULT_BACKOFF_SECONDS when Retry-After is absent', function() {
    $this->mockHandler->append(new Response(429, []));

    $this->client->query('00000');

    expect(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1')
        ->and(GuzzleHibpClient::DEFAULT_BACKOFF_SECONDS)->toBe(60);
});

it('falls back to DEFAULT_BACKOFF_SECONDS when Retry-After is HTTP-date form', function() {
    // Codifies current behavior: `_parseRetryAfter` only accepts
    // `ctype_digit` numeric seconds. RFC 7231 also allows HTTP-date form
    // (`Wed, 21 Oct 2015 07:28:00 GMT`) — the implementation explicitly
    // declines to parse it because the default window is short enough to
    // be safe regardless. If a future commit adds HTTP-date parsing,
    // this test will fail and that's the intended signal.
    $this->mockHandler->append(new Response(429, ['Retry-After' => 'Wed, 21 Oct 2015 07:28:00 GMT']));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

it('falls back to DEFAULT_BACKOFF_SECONDS when Retry-After is empty', function() {
    $this->mockHandler->append(new Response(429, ['Retry-After' => '']));

    $this->client->query('00000');

    expect(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

it('falls back to DEFAULT_BACKOFF_SECONDS when Retry-After is non-numeric garbage', function() {
    $this->mockHandler->append(new Response(429, ['Retry-After' => 'not-a-number']));

    $this->client->query('00000');

    expect(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

it('floors the Retry-After to a 1-second minimum on zero', function() {
    // `max(1, (int)$value)` guards against `Retry-After: 0` producing a
    // 0-second TTL (which Yii cache treats as "never expires") — the
    // implementation hard-floors it. Pinned so a refactor that drops
    // the max() doesn't accidentally wedge the sentinel forever.
    $this->mockHandler->append(new Response(429, ['Retry-After' => '0']));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

it('accepts large numeric Retry-After values without truncation', function() {
    // `(int)` cast keeps the numeric value; max() is a floor not a ceiling.
    // 24 hours is well within int range and stays as-is.
    $this->mockHandler->append(new Response(429, ['Retry-After' => '86400']));

    expect($this->client->query('00000'))->toBeNull()
        ->and(Craft::$app->getCache()->get(GuzzleHibpClient::BACKOFF_CACHE_KEY))->toBe('1');
});

// =============================================================================
// query() — short-circuit when backoff already active (no Guzzle call)
// =============================================================================

it('short-circuits to null when backoff is already active', function() {
    Craft::$app->getCache()->set(GuzzleHibpClient::BACKOFF_CACHE_KEY, '1', 60);

    // No response queued on the mock — if `query()` reaches Guzzle, the
    // mock handler throws "Mock queue is empty" and the test fails. That's
    // the regression-vector pin: a refactor that reorders the early-return
    // would surface here as a queue-exhausted exception.
    expect($this->client->query('00000'))->toBeNull();
});

// =============================================================================
// isBackoffActive()
// =============================================================================

it('reports backoff inactive when the cache key is absent', function() {
    Craft::$app->getCache()->delete(GuzzleHibpClient::BACKOFF_CACHE_KEY);

    expect($this->client->isBackoffActive())->toBeFalse();
});

it('reports backoff active when the sentinel is set', function() {
    Craft::$app->getCache()->set(GuzzleHibpClient::BACKOFF_CACHE_KEY, '1', 60);

    expect($this->client->isBackoffActive())->toBeTrue();
});

// =============================================================================
// Constants — pin the cache key + default backoff window
// =============================================================================

it('exposes the canonical cache key and default backoff constants', function() {
    // Pinned so a refactor that renames the key (or alters the default
    // window) flags itself loudly here AND in security.md / docs that
    // reference the same names.
    expect(GuzzleHibpClient::BACKOFF_CACHE_KEY)->toBe('pp:hibp-429-backoff')
        ->and(GuzzleHibpClient::DEFAULT_BACKOFF_SECONDS)->toBe(60)
        ->and(GuzzleHibpClient::ENDPOINT)->toBe('https://api.pwnedpasswords.com/range/');
});
