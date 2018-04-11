<?php
/**
 * Scout plugin for Craft CMS 3.x.
 *
 * Craft Scout provides a simple solution for adding full-text search to your entries. Scout will automatically keep your search indexes in sync with your entries.
 *
 * @link      https://rias.be
 *
 * @copyright Copyright (c) 2017 Rias
 */

namespace rias\passwordpolicy\services;

use Craft;
use craft\base\Component;
use craft\feeds\GuzzleClient;
use GuzzleHttp\Exception\ClientException;
use rias\passwordpolicy\models\Settings;
use rias\passwordpolicy\PasswordPolicy;
use rias\scout\Scout;

/**
 * @author    Rias
 *
 * @since     0.1.0
 */
class PasswordService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * @var Settings
     */
    private $settings;

    public function init()
    {
        $this->settings = PasswordPolicy::$plugin->settings;
    }

    public function getValidationErrors(string $password) : array
    {
        $errors = [];

        if (strlen($password) < $this->settings->minLength) {
            $errors[] = Craft::t('password-policy', 'Password needs to be at least {min} characters.', ['min' => $this->settings->minLength]);
        }

        if (strlen($password) > $this->settings->maxLength) {
            $errors[] = Craft::t('password-policy', 'Password needs to be less than {max} characters.', ['max' => $this->settings->maxLength]);
        }

        if ($this->settings->cases && !$this->containsDifferentCases($password)) {
            $errors[] = Craft::t('password-policy', 'Password needs to be both upper- and lower-case.');
        }

        if ($this->settings->numbers && !$this->containsNumbers($password)) {
            $errors[] = Craft::t('password-policy', 'Password needs to contain at least 1 numeric character.');
        }

        if ($this->settings->symbols && !$this->containsSymbols($password)) {
            $errors[] = Craft::t('password-policy', 'Password needs to contain at least 1 symbol like @, #, $');
        }

        if ($this->settings->checkPwned && $this->hasBeenPwned($password)) {
            $errors[] = Craft::t('password-policy', 'Password has been Pwned (https://haveibeenpwned.com/Passwords).');
        }

        return $errors;
    }

    protected function containsDifferentCases(string $password) : bool
    {
        return (bool) preg_match('/[A-Z]/', $password) && (bool) preg_match('/[a-z]/', $password);
    }

    protected function containsNumbers(string $password) : bool
    {
        return (bool) preg_match('/\d/', $password);
    }

    protected function containsSymbols(string $password) : bool
    {
        return (bool) preg_match('/[^a-zA-Z\d]/', $password);
    }

    protected function hasBeenPwned(string $password) : bool
    {
        $client = new GuzzleClient();

        try {
            $response = $client->get("https://api.pwnedpasswords.com/pwnedpassword/{$password}");
        } catch (ClientException $e) {
            if ($e->getResponse()->getStatusCode() === 404) {
                return false;
            }
        }

        if ($response->getStatusCode() !== 404) {
            return true;
        }

        return false;
    }
}
