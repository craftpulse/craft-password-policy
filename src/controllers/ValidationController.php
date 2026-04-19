<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Craft;
use craft\elements\User;
use craft\web\Controller;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\validators\CommonPasswordValidator;
use craftpulse\passwordpolicy\validators\MinimumCharacterTypesValidator;
use craftpulse\passwordpolicy\validators\RepeatedCharsValidator;
use craftpulse\passwordpolicy\validators\SequentialCharsValidator;
use yii\web\Response;

/**
 * Class ValidationController
 *
 * AJAX endpoint for real-time password validation. Returns per-rule
 * pass/fail results for the front-end validation checklist.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ValidationController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int|string>|bool|int allow anonymous access for front-end registration forms
     */
    protected array|bool|int $allowAnonymous = ['validate'];

    // Public Methods
    // =========================================================================

    /**
     * Validates a password against the current policy and returns per-rule results.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionValidate(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();

        $request = Craft::$app->getRequest();
        $password = $request->getRequiredBodyParam('password');

        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();
        $isPro = $plugin->getIsPro();

        // Build a temporary user model for contextual validation
        $user = $this->_buildTempUser($request);

        $rules = [];

        // Min length
        $rules[] = [
            'key' => 'minLength',
            'pass' => strlen($password) >= $settings->minLength,
            'message' => Craft::t('password-policy', 'At least {min} characters', ['min' => $settings->minLength]),
        ];

        // Max length
        if ($settings->maxLength > 0) {
            $rules[] = [
                'key' => 'maxLength',
                'pass' => strlen($password) <= $settings->maxLength,
                'message' => Craft::t('password-policy', 'No more than {max} characters', ['max' => $settings->maxLength]),
            ];
        }

        // Complexity: individual or minimum
        if ($isPro && $settings->complexityMode === 'minimum' && $settings->minimumCharacterTypes > 0) {
            $validator = new MinimumCharacterTypesValidator();
            $rules[] = [
                'key' => 'characterTypes',
                'pass' => $validator->validateValue($password) === null,
                'message' => Craft::t('password-policy', 'At least {count} of 4 character types', ['count' => $settings->minimumCharacterTypes]),
            ];
        } else {
            if ($settings->cases) {
                $rules[] = [
                    'key' => 'cases',
                    'pass' => (bool)preg_match('/[a-z]/', $password) && (bool)preg_match('/[A-Z]/', $password),
                    'message' => Craft::t('password-policy', 'Upper and lowercase letters'),
                ];
            }
            if ($settings->numbers) {
                $rules[] = [
                    'key' => 'numbers',
                    'pass' => (bool)preg_match('/[0-9]/', $password),
                    'message' => Craft::t('password-policy', 'At least one number'),
                ];
            }
            if ($settings->symbols) {
                $rules[] = [
                    'key' => 'symbols',
                    'pass' => (bool)preg_match('/[^a-zA-Z0-9]/', $password),
                    'message' => Craft::t('password-policy', 'At least one special character'),
                ];
            }
        }

        // Sequential chars (Pro)
        if ($isPro && $settings->checkSequentialChars) {
            $validator = new SequentialCharsValidator();
            $rules[] = [
                'key' => 'sequential',
                'pass' => $validator->validateValue($password) === null,
                'message' => Craft::t('password-policy', 'No sequential characters'),
            ];
        }

        // Repeated chars (Pro)
        if ($isPro && $settings->checkRepeatedChars) {
            $validator = new RepeatedCharsValidator();
            $rules[] = [
                'key' => 'repeated',
                'pass' => $validator->validateValue($password) === null,
                'message' => Craft::t('password-policy', 'No repeated characters'),
            ];
        }

        // Common passwords (Pro)
        if ($isPro && $settings->checkCommonPasswords) {
            $validator = new CommonPasswordValidator();
            $rules[] = [
                'key' => 'common',
                'pass' => $validator->validateValue($password) === null,
                'message' => Craft::t('password-policy', 'Not a common password'),
            ];
        }

        // HIBP check (async-friendly — returns null if still checking)
        if ($settings->pwned) {
            $result = $plugin->getPasswords()->pwned($password);
            $rules[] = [
                'key' => 'pwned',
                'pass' => $result === null ? null : !$result,
                'message' => Craft::t('password-policy', 'Not found in breach database'),
            ];
        }

        $isValid = true;
        foreach ($rules as $rule) {
            if ($rule['pass'] === false) {
                $isValid = false;
                break;
            }
        }

        return $this->asJson([
            'isValid' => $isValid,
            'rules' => $rules,
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds a temporary User model from request params for contextual validation.
     *
     * @param \craft\web\Request $request
     * @return User
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildTempUser(\craft\web\Request $request): User
    {
        /** @var User|null $currentUser */
        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser !== null) {
            return $currentUser;
        }

        // Anonymous user — build from request params
        $user = new User();
        $user->username = $request->getBodyParam('username');
        $user->email = $request->getBodyParam('email');

        return $user;
    }
}
