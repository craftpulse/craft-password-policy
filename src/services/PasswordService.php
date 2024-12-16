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
    public const PWNED_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    /**
     * @var SettingsModel
     */
    private SettingsModel $settings;

    public function init(): void
    {
        $this->settings = PasswordPolicy::$plugin->settings;
    }

    /**
     * Method the generate the password pattern.
     * @return string
     */
    public function generatePattern(): string
    {
        // build the regexp dynamically
        $pattern = $this->patterns()
            ->reject(function(string $value, string $key) {
                return $this->settings->{$key} === false;
            })
            ->implode('');

        return '/^' . $pattern . '/';
    }

    /**
     * Method to generate the validation message.
     * @return string
     */
    public function generateMessage(): string
    {
        // build the regexp dynamically
        $message = $this->messages()
            ->reject(function(string $value, string $key) {
                return $this->settings->{$key} === false;
            })
            ->implode(', ');

        return preg_replace('/,(?=[^,]*$)/', Craft::t('password-policy', ' and '), $message);
    }

    /**
     * Method to validate password against the "have I been pwned" database
     * @return bool
     */
    public function pwned(string $password): ?bool
    {
        $hash = strtoupper(sha1('password'));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $endpoint = self::PWNED_ENDPOINT . $prefix;

        try {
            $client = Craft::createGuzzleClient([
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

            return $passwords->count() > 0 ? true : false;
        } catch (GuzzleException $exception) {
            PasswordPolicy::$plugin->log($exception->getMessage(), [], Logger::LEVEL_ERROR);
            return false;
        }
    }

    /**
     * Collection of messages.
     * @return Collection
     */
    private function messages(): Collection
    {
        return Collection::make([
            'cases' => Craft::t('password-policy', 'a lowercase character, an uppercase character'),
            'numbers' => Craft::t('password-policy', 'a number'),
            'symbols' => Craft::t('password-policy', 'a special character.'),
        ]);
    }

    /**
     * Collection of regexp patterns.
     * @return Collection
     */
    private function patterns(): Collection
    {
        return Collection::make([
            'cases' => '(?=.*[a-z])(?=.*[A-Z])',
            'numbers' => '(?=.*[0-9])',
            'symbols' => '(?=.*[!@#\$%\^&\*])',
        ]);
    }
}
