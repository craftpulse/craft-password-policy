<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craftpulse\passwordpolicy\services\HibpClientInterface;

/**
 * Test double for the HIBP range-API client.
 *
 * Lets `PasswordService::hibp()` and the HIBP-on-login listener be exercised
 * without hitting the live HIBP endpoint. The fake records every call to
 * [[query()]] so tests can assert the short-circuit branches actually
 * skip the network round-trip.
 *
 * Privacy: the fake never logs the prefix it receives — `$queryCalls` only
 * tracks the count and the prefix arguments are discarded. Tests that care
 * about prefix shape should assert on the SHA-1 of a known input directly.
 *
 * Wiring pattern (`beforeEach`):
 *
 * ```
 * $fake = new HibpClientFake();
 * PasswordPolicy::$plugin->set('hibpClient', $fake);
 * ```
 *
 * The DI container's `set()` swaps the singleton for the duration of the
 * Yii component scope; the next `getHibpClient()` returns the fake.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class HibpClientFake implements HibpClientInterface
{
    // Public Properties
    // =========================================================================

    /**
     * Whether [[isBackoffActive()]] should report the site-wide backoff as
     * set. Toggle in a test to exercise the short-circuit branches that
     * production wires up against the cache key sentinel.
     *
     * @var bool
     *
     * @since 5.2.0
     */
    public bool $backoffActive = false;

    /**
     * Number of times [[query()]] has been called. Tests that assert the
     * short-circuit branches don't hit the API verify this stays 0; happy
     * path tests verify it reaches the expected count.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public int $queryCalls = 0;

    /**
     * Captured prefix arguments from every [[query()]] call, in order.
     * Useful for verifying that the consumer hashes + slices a password
     * down to the canonical 5-uppercase-hex shape before hitting the API.
     *
     * @var string[]
     *
     * @since 5.2.0
     */
    public array $queryPrefixes = [];

    /**
     * Body to return from [[query()]] on the next call. `null` simulates
     * a fail-open response (API unreachable, non-2xx, etc.) so consumer
     * code that disambiguates "unable to check" from "not breached" can
     * be exercised.
     *
     * @var string|null
     *
     * @since 5.2.0
     */
    public ?string $nextResponse = '';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isBackoffActive(): bool
    {
        return $this->backoffActive;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function query(string $sha1Prefix): ?string
    {
        $this->queryCalls++;
        $this->queryPrefixes[] = $sha1Prefix;

        return $this->nextResponse;
    }

    /**
     * Convenience: set the next response to a HIBP range-API body that
     * declares the supplied SHA-1 hash as breached. Caller passes the FULL
     * uppercase SHA-1 hash; the fake builds the `SUFFIX:COUNT` line for the
     * trailing 35 chars (matching what HIBP's range API returns when the
     * 5-char prefix lookup hits).
     *
     * Privacy: the SHA-1 hash NEVER lands in a log line. The fake stores
     * the response body in memory only; tests that assert on the breached
     * outcome look at the boolean PasswordService returns, not at the body.
     *
     * @param string $sha1Hash full uppercase SHA-1 (40 hex chars)
     * @param int $count breach occurrence count to embed (cosmetic — the
     *     consumer doesn't read it)
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function setBreachedHash(string $sha1Hash, int $count = 1): void
    {
        $suffix = substr($sha1Hash, 5);

        // HIBP's API sends `\r\n`-separated lines. Mirror that so the
        // consumer's `explode("\r\n", $body)` parse sees the production
        // shape.
        $this->nextResponse = "{$suffix}:{$count}\r\nDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:7";
    }

    /**
     * Convenience: set the next response to a HIBP range body that does
     * NOT contain the consumer's SHA-1 suffix. Used for the "not breached"
     * happy path. The body still has at least one row so the body-empty
     * branch isn't accidentally exercised.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function setCleanResponse(): void
    {
        $this->nextResponse = "0000000000000000000000000000000000A:1\r\n0000000000000000000000000000000000B:42";
    }
}
