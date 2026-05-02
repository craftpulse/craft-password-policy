<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

/**
 * Contract for the "Have I Been Pwned" range-API client.
 *
 * Decouples the HTTP transport (Guzzle, mock, curl, anything else) from the
 * password-checking orchestration in `PasswordService`. Tests swap in a fake
 * client to assert behavior without hitting the live endpoint; production
 * binds `GuzzleHibpClient`.
 *
 * Implementations own:
 * - The HTTP transport (TLS verification, headers, timeouts).
 * - The site-wide 429 backoff sentinel — every consumer must short-circuit
 *   via [[isBackoffActive()]] before calling [[query()]] so a single 429
 *   response suppresses the rest of the request window.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
interface HibpClientInterface
{
    // Public Methods
    // =========================================================================

    /**
     * Whether the site-wide HIBP backoff sentinel is currently set.
     *
     * Callers can short-circuit before requesting the prefix range when this
     * returns true. Implementations MUST consult the same sentinel that
     * [[query()]] writes on a 429 response.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isBackoffActive(): bool;

    /**
     * Fetches the suffix list for the given SHA-1 prefix from the HIBP range
     * API. Returns the raw response body (newline-separated `SUFFIX:COUNT`
     * lines) on success, or `null` on any failure mode the caller should
     * treat as "unable to check": API down, non-2xx response, network error,
     * or active backoff.
     *
     * Privacy contract: the prefix is k-anonymity safe and intentionally
     * what we send to HIBP. Implementations MUST NOT log the full hash, the
     * full response body, or any user-derived material — only operationally
     * useful events ("API returned 429, backoff active for Ns").
     *
     * @param string $sha1Prefix the first 5 hex chars of the password's
     *                            uppercased SHA-1 hash
     * @return string|null the raw response body, or `null` on failure
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function query(string $sha1Prefix): ?string;
}
