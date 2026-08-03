<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
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

use Illuminate\Support\Collection;
use Throwable;

/**
 * Class PasswordService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordService extends Component
{
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
     * Generates a regex pattern for password validation based on the supplied
     * (or global) settings.
     *
     * Pass the user's resolved policy (`PolicyResolverService::resolveForUser()`)
     * to honor per-group complexity overrides — `UserRules::defineRules()` does
     * exactly that. Defaults to the global `SettingsModel` cached in `init()`
     * for AJAX/preview contexts without a target user.
     *
     * @param SettingsModel|null $settings the resolved policy; null for global
     * @return string
     *
     * @author CraftPulse
     * @since 5.0.0
     */
    public function generatePattern(?SettingsModel $settings = null): string
    {
        $settings ??= $this->_settings;

        $pattern = $this->_patterns()
            ->reject(function(string $value, string $key) use ($settings) {
                return $settings->{$key} === false;
            })
            ->implode('');

        return '/^' . $pattern . '/';
    }

    /**
     * Generates a human-readable validation message based on the supplied
     * (or global) settings.
     *
     * Pass the user's resolved policy to honor per-group complexity overrides;
     * defaults to the global `SettingsModel` cached in `init()`.
     *
     * @param SettingsModel|null $settings the resolved policy; null for global
     * @return string
     *
     * @author CraftPulse
     * @since 5.0.0
     */
    public function generateMessage(?SettingsModel $settings = null): string
    {
        $settings ??= $this->_settings;

        $message = $this->_messages()
            ->reject(function(string $value, string $key) use ($settings) {
                return $settings->{$key} === false;
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
        $client = PasswordPolicy::$plugin->getHibpClient();

        // Site-wide backoff sentinel. If HIBP recently 429'd us, every caller
        // skips the network round-trip until the backoff expires. Without
        // this, a high-traffic install with HIBP-on-login enabled would
        // hammer the API while already rate-limited and risk an IP ban.
        if ($client->isBackoffActive()) {
            return null;
        }

        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $body = $client->query($prefix);

        if ($body === null) {
            return null;
        }

        $suffixLines = Collection::make(explode("\r\n", $body));

        $suffixLines = $suffixLines->map(fn($suffixLine) => strtok($suffixLine, ':'))
            ->filter(function($suffixLine) use ($suffix) {
                if ($suffix === $suffixLine) {
                    return true;
                }
            });

        return $suffixLines->isNotEmpty();
    }

    /**
     * Returns whether the site-wide HIBP backoff sentinel is currently set.
     *
     * Thin proxy over [[HibpClientInterface::isBackoffActive()]] so the
     * historical 5.2.0 public API remains stable across the client
     * extraction. Prefer calling the client directly in new code.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isHibpBackoffActive(): bool
    {
        return PasswordPolicy::$plugin->getHibpClient()->isBackoffActive();
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
