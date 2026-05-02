<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\base\Component;
use craftpulse\passwordpolicy\PasswordPolicy;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use yii\log\Logger;

/**
 * Default `HibpClientInterface` implementation backed by Craft's Guzzle
 * client.
 *
 * The HTTP transport is `Craft::createGuzzleClient()` with `verify => true`
 * forced on at the request site — the Guzzle config a host project ships in
 * `config/guzzle.php` MAY disable verification for proxied internal traffic;
 * HIBP is a public CDN over TLS, and we override the project default rather
 * than trust it. Same reasoning behind the explicit `Add-Padding` header:
 * HIBP returns padded responses to prevent length-correlation side-channel
 * attacks against the prefix.
 *
 * 429 handling sets a site-wide backoff sentinel keyed by
 * [[BACKOFF_CACHE_KEY]] with TTL derived from the response's `Retry-After`
 * header (or [[DEFAULT_BACKOFF_SECONDS]] when the header is absent). The
 * sentinel value is the literal string `'1'` — no user-derived material
 * lands in the cache key or value, ever.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GuzzleHibpClient extends Component implements HibpClientInterface
{
    // Constants
    // =========================================================================

    /**
     * HIBP range-API endpoint. The 5-char SHA-1 prefix appends to this URL.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    /**
     * Cache key used to suppress HIBP requests site-wide while the API is
     * rate-limiting us. Set when a 429 response comes back; cleared by TTL
     * (`Retry-After` header, or [[DEFAULT_BACKOFF_SECONDS]] if absent).
     * Single fixed key so every caller checks the same sentinel.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const BACKOFF_CACHE_KEY = 'pp:hibp-429-backoff';

    /**
     * Default backoff window when the 429 response carries no `Retry-After`
     * header (or carries an unparseable value). Conservative — high enough
     * to actually clear the rate-limit on HIBP's side, low enough that a
     * transient throttle doesn't disable HIBP-on-login for an extended
     * period.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_BACKOFF_SECONDS = 60;

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
        return Craft::$app->getCache()->get(self::BACKOFF_CACHE_KEY) !== false;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function query(string $sha1Prefix): ?string
    {
        if ($this->isBackoffActive()) {
            return null;
        }

        $endpoint = self::ENDPOINT . $sha1Prefix;

        try {
            $client = Craft::createGuzzleClient([
                'verify' => true,
                'headers' => [
                    'Add-Padding' => 'true',
                ],
            ]);
            $response = $client->request('GET', $endpoint);

            return $response->getBody()->getContents();
        } catch (ClientException $exception) {
            // 429 Too Many Requests — set the site-wide backoff sentinel
            // and return null so every other caller for the next
            // `Retry-After` window short-circuits before hitting the API.
            $statusCode = $exception->getResponse()->getStatusCode();

            if ($statusCode === 429) {
                $this->_setBackoff($exception);
                return null;
            }

            PasswordPolicy::$plugin->log($exception->getMessage(), [], Logger::LEVEL_ERROR);
            return null;
        } catch (GuzzleException $exception) {
            PasswordPolicy::$plugin->log($exception->getMessage(), [], Logger::LEVEL_ERROR);
            return null;
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Stores the HIBP 429 backoff sentinel in the cache with a TTL derived
     * from the response's `Retry-After` header (seconds-form). Falls back
     * to [[DEFAULT_BACKOFF_SECONDS]] when the header is absent or
     * unparseable.
     *
     * Logs once per backoff window at WARNING — every subsequent
     * short-circuited caller during the window does NOT log. Privacy
     * guard: the sentinel value is the literal `'1'` string, never
     * user-derived material.
     *
     * @param ClientException $exception the 429 response
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _setBackoff(ClientException $exception): void
    {
        $retryAfter = $this->_parseRetryAfter($exception);

        Craft::$app->getCache()->set(
            self::BACKOFF_CACHE_KEY,
            '1',
            $retryAfter,
        );

        Craft::warning(
            "HIBP API returned 429; site-wide backoff active for {$retryAfter}s.",
            'password-policy',
        );
    }

    /**
     * Extracts the `Retry-After` header value (seconds form) from a 429
     * response. Returns [[DEFAULT_BACKOFF_SECONDS]] when the header is
     * absent, non-numeric, or in HTTP-date form (we don't parse dates here
     * to keep the path simple — the default window is short enough to be
     * safe regardless).
     *
     * @param ClientException $exception
     * @return int seconds
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _parseRetryAfter(ClientException $exception): int
    {
        $headers = $exception->getResponse()->getHeader('Retry-After');

        if (empty($headers)) {
            return self::DEFAULT_BACKOFF_SECONDS;
        }

        $value = trim($headers[0]);

        if (!ctype_digit($value)) {
            return self::DEFAULT_BACKOFF_SECONDS;
        }

        return max(1, (int)$value);
    }
}
