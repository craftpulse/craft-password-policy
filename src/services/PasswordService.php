<?php
/**
 * Scout plugin for Craft CMS 3.x.
 *
 * Craft Scout provides a simple solution for adding full-text search to your entries. Scout will automatically keep your search indexes in sync with your entries.
 *
 * @link      https://percipio.london
 *
 * @copyright Copyright (c) 2020 Percipio Global Ltd.
 */

namespace percipiolondon\passwordpolicy\services;

use Craft;
use craft\base\Component;
use craft\elements\User;
use percipiolondon\passwordpolicy\models\Settings;
use percipiolondon\passwordpolicy\PasswordPolicy;

/**
 * @author    Percipio Global Ltd.
 *
 * @since     1.0.0
 */
class PasswordService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * @var Settings
     */
    private Settings $settings;

    public function init(): void
    {
        $this->settings = PasswordPolicy::$plugin->settings;
    }

    public function sendPasswordReset(): void
    {

    }

    public function getValidationErrors(string $password): array
    {
        $errors = [];

        if ($password === '' || strlen($password) < $this->settings->minLength) {
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

        return $errors;
    }

    protected function containsDifferentCases(string $password): bool
    {
        return preg_match('/[A-Z]/', $password) && preg_match('/[a-z]/', $password);
    }

    protected function containsNumbers(string $password): bool
    {
        return (bool) preg_match('/\d/', $password);
    }

    protected function containsSymbols(string $password): bool
    {
        return (bool) preg_match('/[^a-zA-Z\d]/', $password);
    }
}
