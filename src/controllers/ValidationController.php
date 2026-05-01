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
        $isPro = $plugin->getIsPro();

        // Build a temporary user model for contextual validation
        $user = $this->_buildTempUser($request);

        // Resolve effective policy — uses per-group policies if the user
        // belongs to groups, otherwise returns global settings. Anonymous
        // group preview (caller passes `groups[]` body param) sets a
        // groups array on the temp user without an id; the resolver
        // honors `getGroups()` regardless of id.
        $settings = ($user->id !== null || !empty($user->getGroups()))
            ? $plugin->getPolicyResolver()->resolveForUser($user)
            : $plugin->getSettings();

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
        if ($settings->hibp) {
            $result = $plugin->getPasswords()->hibp($password);
            $rules[] = [
                'key' => 'hibp',
                'pass' => $result === null ? null : !$result,
                'message' => Craft::t('password-policy', 'Not found in breach database'),
            ];
        }

        $isValid = true;
        $errorsByKey = [];

        foreach ($rules as $rule) {
            if ($rule['pass'] === false) {
                $isValid = false;
                $errorsByKey[$rule['key']] = $rule['message'];
            }
        }

        // Map response key aliases for the front-end JS — the JS toggles
        // `data-pp-requirement="<key>"` items, and those use the keys
        // emitted by `requirementRules()` (`length`, `cases`, `numbers`,
        // `symbols`, `character-types`, `blocklist`, `hibp`).
        $clientErrorsByKey = [];

        foreach ($errorsByKey as $key => $message) {
            $clientErrorsByKey[$this->_clientKey($key)] = $message;
        }

        // Strength block — Engine A baseline always; Engine B (zxcvbn-php)
        // when Pro + setting + library installed (StrengthService picks).
        $blocklistHit = isset($errorsByKey['common']);
        $strength = $plugin->getStrength()->compute(
            $password,
            $settings,
            [
                'username' => (string)($request->getBodyParam('username') ?? ''),
                'email' => (string)($request->getBodyParam('email') ?? ''),
            ],
            $blocklistHit,
        );

        return $this->asJson([
            'isValid' => $isValid,
            'passed' => $isValid,
            'errorsByKey' => $clientErrorsByKey,
            'errors' => array_values($clientErrorsByKey),
            'rules' => $rules,
            'strength' => $strength,
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

        // Group-preview path: caller passed `groups[]` (handles) — resolve
        // and assign to the temp user so the policy resolver returns the
        // per-group merged policy.
        $groupHandles = (array)$request->getBodyParam('groups', []);

        if (!empty($groupHandles)) {
            $groups = [];

            foreach ($groupHandles as $handle) {
                $group = Craft::$app->getUserGroups()->getGroupByHandle((string)$handle);

                if ($group !== null) {
                    $groups[] = $group;
                }
            }

            if (!empty($groups)) {
                $user->setGroups($groups);
                // Set a dummy id so PolicyResolverService::resolveForUser
                // takes the per-group code path (it returns global when
                // user has no groups, but our setGroups call is sufficient
                // — id only matters if downstream code queries the DB).
            }
        }

        return $user;
    }

    /**
     * Maps an internal validate-rule key to the front-end requirement key
     * used in `data-pp-requirement="<key>"` markup.
     *
     * @param string $key the internal key
     * @return string the client-facing key
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _clientKey(string $key): string
    {
        return match ($key) {
            'minLength', 'maxLength' => 'length',
            'characterTypes' => 'character-types',
            'common' => 'blocklist',
            default => $key,
        };
    }
}
