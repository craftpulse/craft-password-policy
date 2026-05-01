<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\base\Component;
use craft\db\Table;
use craft\elements\User;
use craft\helpers\Db;

use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Collection;
use Throwable;
use yii\log\Logger;

/**
 * Class PasswordService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordService extends Component
{
    // Constants
    // =========================================================================

    public const HIBP_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    /**
     * Cache key used to suppress HIBP requests site-wide while the API is
     * rate-limiting us. Set when a 429 response comes back; cleared by TTL
     * (`Retry-After` header, or the default below if absent). Single fixed
     * key so every caller checks the same sentinel.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const HIBP_BACKOFF_CACHE_KEY = 'pp:hibp-429-backoff';

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
    public const HIBP_DEFAULT_BACKOFF_SECONDS = 60;

    /**
     * @var string
     *
     * @deprecated in 5.2.0. Use [[HIBP_ENDPOINT]] instead.
     */
    public const PWNED_ENDPOINT = self::HIBP_ENDPOINT;

    // Private Properties
    // =========================================================================

    /**
     * @var SettingsModel
     */
    private SettingsModel $_settings;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function init(): void
    {
        $this->_settings = PasswordPolicy::$plugin->getSettings();
    }

    /**
     * Generates a regex pattern for password validation based on the current settings.
     *
     * @return string
     *
     * @author CraftPulse
     */
    public function generatePattern(): string
    {
        $pattern = $this->_patterns()
            ->reject(function(string $value, string $key) {
                return $this->_settings->{$key} === false;
            })
            ->implode('');

        return '/^' . $pattern . '/';
    }

    /**
     * Generates a human-readable validation message based on the current settings.
     *
     * @return string
     *
     * @author CraftPulse
     */
    public function generateMessage(): string
    {
        $message = $this->_messages()
            ->reject(function(string $value, string $key) {
                return $this->_settings->{$key} === false;
            })
            ->implode(', ');

        return preg_replace('/,(?=[^,]*$)/', Craft::t('password-policy', ' and '), $message);
    }

    /**
     * Validates a password against the "Have I Been Pwned" database.
     *
     * Returns true if breached, false if clean, null on API failure.
     * The null return allows callers to distinguish "not breached" from
     * "unable to check" for fail-open/fail-closed handling.
     *
     * @param string $password
     * @return bool|null true = breached, false = clean, null = API failure
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function hibp(#[\SensitiveParameter] string $password): ?bool
    {
        // Site-wide backoff sentinel. If HIBP recently 429'd us, every caller
        // skips the network round-trip until the backoff expires. Without
        // this, a high-traffic install with HIBP-on-login enabled would
        // hammer the API while already rate-limited and risk an IP ban.
        if ($this->isHibpBackoffActive()) {
            return null;
        }

        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $endpoint = self::HIBP_ENDPOINT . $prefix;

        try {
            $client = Craft::createGuzzleClient([
                'verify' => true,
                'headers' => [
                    'Add-Padding' => 'true',
                ],
            ]);
            $response = $client->request('GET', $endpoint);
            $passwords = Collection::make(explode("\r\n", $response->getBody()->getContents()));

            $passwords = $passwords->map(fn($password) => strtok($password, ':'))
                ->filter(function($password) use ($suffix) {
                    if ($suffix === $password) {
                        return true;
                    }
                });

            return $passwords->isNotEmpty();
        } catch (ClientException $exception) {
            // 429 Too Many Requests — set the site-wide backoff sentinel and
            // return null so every other caller for the next `Retry-After`
            // window short-circuits before hitting the API.
            $statusCode = $exception->getResponse()->getStatusCode();

            if ($statusCode === 429) {
                $this->_setHibpBackoff($exception);
                return null;
            }

            PasswordPolicy::$plugin->log($exception->getMessage(), [], Logger::LEVEL_ERROR);
            return null;
        } catch (GuzzleException $exception) {
            PasswordPolicy::$plugin->log($exception->getMessage(), [], Logger::LEVEL_ERROR);
            return null;
        }
    }

    /**
     * Returns whether the site-wide HIBP backoff sentinel is currently set.
     *
     * Callers can short-circuit before hitting the network when this returns
     * true. The sentinel value is the literal string `'1'` — no user-derived
     * material ever lands in the cache key or value.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isHibpBackoffActive(): bool
    {
        return Craft::$app->getCache()->get(self::HIBP_BACKOFF_CACHE_KEY) !== false;
    }

    /**
     * Validates a password against the "Have I Been Pwned" database.
     *
     * @param string $password
     * @return bool|null true = breached, false = clean, null = API failure
     *
     * @deprecated in 5.2.0. Use [[hibp()]] instead.
     *
     * @author CraftPulse
     */
    public function pwned(#[\SensitiveParameter] string $password): ?bool
    {
        return $this->hibp($password);
    }

    /**
     * Destroys all session rows for the given user except the current request's
     * session token (when one is in scope).
     *
     * Called explicitly from the front-end password-change flow so the
     * just-changed-password user keeps their current session but every other
     * device/browser is logged out. Belt-and-braces: Craft's `User::afterSave`
     * already runs this same delete when `newPassword` is set, but having an
     * explicit service method makes the contract visible at the call site and
     * survives any future Craft refactor of that internal hook.
     *
     * Defensive: failures here never throw — the password change has already
     * succeeded, and a transient DB issue on the sessions table shouldn't
     * surface as a generic "couldn't update password" to the user.
     *
     * @param User $user the user whose other sessions should be invalidated
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function destroyOtherSessions(User $user): void
    {
        if (!$user->id) {
            return;
        }

        try {
            $condition = ['userId' => $user->id];

            // `getToken()` only exists on the web `User` component — the
            // console `User` doesn't carry session tokens. Only ask for the
            // current token on web requests, otherwise fall through to the
            // bare userId condition (deletes every session for the user).
            if (!Craft::$app->getRequest()->getIsConsoleRequest()) {
                $token = Craft::$app->getUser()->getToken();

                if ($user->getIsCurrent() && $token !== null) {
                    $condition = ['and', $condition, ['not', ['token' => $token]]];
                }
            }

            Db::delete(Table::SESSIONS, $condition);
        } catch (Throwable $e) {
            Craft::warning(
                'Failed to destroy other sessions for user ' . $user->id . ': ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Stores the HIBP 429 backoff sentinel in the cache with a TTL derived
     * from the response's `Retry-After` header (seconds-form). Falls back to
     * `HIBP_DEFAULT_BACKOFF_SECONDS` when the header is absent or unparseable.
     *
     * Logs once per backoff window at WARNING — every subsequent
     * short-circuited caller during the window does NOT log. Privacy guard:
     * the sentinel value is the literal `'1'` string, never user-derived
     * material.
     *
     * @param ClientException $exception the 429 response
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _setHibpBackoff(ClientException $exception): void
    {
        $retryAfter = $this->_parseRetryAfter($exception);

        Craft::$app->getCache()->set(
            self::HIBP_BACKOFF_CACHE_KEY,
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
     * response. Returns `HIBP_DEFAULT_BACKOFF_SECONDS` when the header is
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
            return self::HIBP_DEFAULT_BACKOFF_SECONDS;
        }

        $value = trim($headers[0]);

        if (!ctype_digit($value)) {
            return self::HIBP_DEFAULT_BACKOFF_SECONDS;
        }

        return max(1, (int)$value);
    }

    /**
     * Returns the collection of human-readable requirement messages.
     *
     * @return Collection
     *
     * @author CraftPulse
     */
    private function _messages(): Collection
    {
        return Collection::make([
            'cases' => Craft::t('password-policy', 'a lowercase character, an uppercase character'),
            'numbers' => Craft::t('password-policy', 'a number'),
            'symbols' => Craft::t('password-policy', 'a special character.'),
        ]);
    }

    /**
     * Returns the collection of regex patterns for password requirements.
     *
     * @return Collection
     *
     * @author CraftPulse
     */
    private function _patterns(): Collection
    {
        return Collection::make([
            'cases' => '(?=.*[a-z])(?=.*[A-Z])',
            'numbers' => '(?=.*[0-9])',
            'symbols' => '(?=.*[^a-zA-Z0-9])',
        ]);
    }
}
