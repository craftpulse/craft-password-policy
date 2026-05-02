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

use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;

use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Collection;
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

    public const PWNED_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

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
     * @param string $password
     * @return bool|null
     *
     * @author CraftPulse
     */
    public function pwned(string $password): ?bool
    {
        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $endpoint = self::PWNED_ENDPOINT . $prefix;

        try {
            $client = Craft::createGuzzleClient([
                'headers' => [
                    'Add-Padding' => 'true',
                ],
                // Force TLS verification on HIBP requests regardless of any
                // site-level config/guzzle.php override. The Pwned Passwords
                // API is only meaningful over a verified TLS channel.
                'verify' => true,
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
        } catch (GuzzleException $exception) {
            PasswordPolicy::$plugin->log($exception->getMessage(), [], Logger::LEVEL_ERROR);
            return false;
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
