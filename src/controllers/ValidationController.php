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
use craft\validators\UserPasswordValidator;
use craft\web\Controller;
use craftpulse\passwordpolicy\filters\IpRateLimit;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\validators\CommonPasswordValidator;
use craftpulse\passwordpolicy\validators\MinimumCharacterTypesValidator;
use craftpulse\passwordpolicy\validators\RepeatedCharsValidator;
use craftpulse\passwordpolicy\validators\SequentialCharsValidator;
use yii\filters\RateLimiter;
use yii\web\Response;

/**
 * Class ValidationController
 *
 * AJAX endpoint for real-time password validation. Returns per-rule
 * pass/fail results for the front-end validation checklist.
 *
 * The endpoint is anonymous-allowed because registration and reset forms
 * need it before a session exists, which makes it the plugin's most
 * exposed surface and the reason for the three limits below:
 *
 *  - A per-IP rate limit ({@see self::behaviors()}), because the response
 *    is CPU-bound.
 *  - A plaintext length ceiling ({@see self::MAX_PASSWORD_LENGTH}), because
 *    zxcvbn's matchers are roughly quadratic in input length.
 *  - No live breach lookup for anonymous callers
 *    ({@see self::actionValidate()}), because a shared upstream rate limit
 *    can't be defended by a per-IP one.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ValidationController extends Controller
{
    // Constants
    // =========================================================================

    /**
     * Burst capacity per IP on `actionValidate()`, refilling over
     * {@see self::RATE_LIMIT_WINDOW} seconds.
     *
     * Sized off the reference client, which debounces at 250ms: continuous
     * typing produces at most four requests a second, and one form fill runs
     * to roughly twenty. Sixty absorbs two or three fills back to back and
     * then meters the IP to one request a second, which is far below what it
     * takes to make this endpoint's CPU cost matter. A shared NAT that
     * exhausts the bucket loses live feedback, not the ability to register:
     * the save-path validators are the authoritative gate and are untouched
     * by this.
     *
     * @since 5.2.0
     */
    public const RATE_LIMIT = 60;

    /**
     * Seconds {@see self::RATE_LIMIT} refills over.
     *
     * @since 5.2.0
     */
    public const RATE_LIMIT_WINDOW = 60;

    /**
     * Hard cap on the plaintext length this endpoint will analyse.
     *
     * Pinned to Craft's own ceiling: `craft\validators\UserPasswordValidator`
     * refuses to save anything longer, so analysing past it is work spent on a
     * password that can never exist. It matters because zxcvbn's matchers are
     * roughly O(n squared), so the previous 4096-character cap let one
     * anonymous request cost several hundred times what a real password does.
     *
     * @since 5.2.0
     */
    private const MAX_PASSWORD_LENGTH = UserPasswordValidator::MAX_PASSWORD_LENGTH;

    // Public Properties
    // =========================================================================

    /**
     * @var array<int|string>|bool|int allow anonymous access for front-end registration forms
     */
    protected array|bool|int $allowAnonymous = ['validate'];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Attaches a per-IP rate limit to `validate`. The endpoint is
     * anonymous-allowed and its response is CPU-bound (zxcvbn plus every
     * configured validator), so without a limit a single caller can spend a
     * site's CPU budget from a laptop.
     *
     * Yii's `RateLimiter` meters `Yii::$app->user->getIdentity()` by default
     * and does nothing when there isn't one, which on an anonymous endpoint is
     * every request. The identity is therefore supplied explicitly, keyed on
     * IP, and it applies to authenticated callers too: a session is not
     * evidence of restraint.
     *
     * Rate-limit headers are suppressed, matching Craft core's own limited
     * anonymous endpoint (`UsersController::behaviors()`). There is no reason
     * to hand an attacker the exact shape of the bucket.
     *
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function behaviors(): array
    {
        return parent::behaviors() + [
            'rateLimiter' => [
                'class' => RateLimiter::class,
                'only' => ['validate'],
                'enableRateLimitHeaders' => false,
                'user' => fn() => new IpRateLimit([
                    'limit' => self::RATE_LIMIT,
                    'window' => self::RATE_LIMIT_WINDOW,
                    'keyPrefix' => 'pp:validate',
                    'ip' => Craft::$app->getRequest()->getUserIP() ?? 'unknown',
                ]),
            ],
        ];
    }

    /**
     * Validates a password against the current policy and returns per-rule results.
     *
     * Anonymous callers get no live breach lookup; the `hibp` rule comes back
     * with `pass = null` for them. The inline comment on that branch carries
     * the reasoning, and `HibpValidator` on the save path is unaffected either
     * way.
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

        // Coerce to string — `password[]=x` would otherwise hand
        // `getRequiredBodyParam` an array and 500 an anonymous endpoint (a
        // raw `(string)` cast would emit an "Array to string conversion"
        // warning). Non-scalar input collapses to an empty string.
        $passwordParam = $request->getRequiredBodyParam('password');
        $password = is_scalar($passwordParam) ? (string)$passwordParam : '';

        // The submitted length is captured BEFORE the clamp, so the length
        // rules below judge what the caller actually sent. Only the expensive
        // analysis (pattern validators, SHA-1 prefix, zxcvbn) runs on the
        // clamped copy: those are quadratic-ish in input length and the
        // discarded tail belongs to a password Craft would refuse to save
        // anyway.
        $length = mb_strlen($password);

        if ($length > self::MAX_PASSWORD_LENGTH) {
            $password = mb_substr($password, 0, self::MAX_PASSWORD_LENGTH);
        }

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

        // Min length — counted in code points, not bytes, so multibyte
        // passwords agree with Yii's `string` validator on the save path.
        $rules[] = [
            'key' => 'minLength',
            'pass' => $length >= $settings->minLength,
            'message' => Craft::t('password-policy', 'At least {min} characters', ['min' => $settings->minLength]),
        ];

        // Max length
        if ($settings->maxLength > 0) {
            $rules[] = [
                'key' => 'maxLength',
                'pass' => $length <= $settings->maxLength,
                'message' => Craft::t('password-policy', 'No more than {max} characters', ['max' => $settings->maxLength]),
            ];
        }

        // Complexity: individual or minimum
        if ($isPro && $settings->complexityMode === 'minimum' && $settings->minimumCharacterTypes > 0) {
            // Thread the resolved per-user requirement into the validator so a
            // per-group override drives the live checklist, not the global value.
            $validator = new MinimumCharacterTypesValidator([
                'minimumCharacterTypes' => $settings->minimumCharacterTypes,
            ]);
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

        // Common passwords (all editions since 5.2.0).
        //
        // Enterprise resolves the user's policy IDs and scopes the
        // validator to global + per-policy entries (G6). Pro/Lite — and
        // anonymous Enterprise requests — leave `policyIds` null, which
        // collapses to global-only matching. We never trust anonymous
        // POST to identify a user; the per-policy filter only applies
        // when an authenticated identity is present in the session.
        if ($settings->checkCommonPasswords) {
            $validator = new CommonPasswordValidator([
                'policyIds' => $this->_resolvePolicyIdsForRequest($user),
            ]);
            $rules[] = [
                'key' => 'common',
                'pass' => $validator->validateValue($password) === null,
                'message' => Craft::t('password-policy', 'Not a common password'),
            ];
        }

        // HIBP check (async-friendly — pass is null when the answer is unknown).
        //
        // Anonymous callers never reach the network. A 429 from HIBP sets a
        // site-wide backoff for up to 24 hours, during which `hibp()` returns
        // null for EVERY caller and `HibpValidator` fail-opens under the
        // default `hibpFailMode = 'open'` — so an unauthenticated caller who
        // can drive this endpoint can switch breach checking off across the
        // whole site, on the real password-save path and on login, for a day.
        // The per-IP rate limit above does not close that: the backoff is one
        // shared global bucket reached through the site's single egress IP, so
        // a handful of source addresses stays under any per-IP limit and still
        // trips it. The only structural fix is to keep unauthenticated input
        // off the wire. It also stops the endpoint being a free HIBP proxy
        // through the customer's egress IP.
        //
        // The rule is still emitted with `pass = null`, the same shape the
        // client already renders as an unverified in-progress state. Dropping
        // it instead would tell a visitor there is no breach requirement at
        // all, and there is: `HibpValidator` runs on save regardless of what
        // this hint said, so an anonymous registrant who picks a breached
        // password is still refused. What degrades is the live hint, not the
        // control.
        if ($settings->hibp) {
            $isAnonymous = Craft::$app->getUser()->getIdentity() === null;
            $result = $isAnonymous ? null : $plugin->getPasswords()->hibp($password);
            $rules[] = [
                'key' => 'hibp',
                'pass' => $result === null ? null : !$result,
                'message' => Craft::t('password-policy', 'Not found in breach database'),
            ];
        }

        $isValid = true;
        $errorsByKey = [];
        $pendingKeys = [];

        foreach ($rules as $rule) {
            if ($rule['pass'] === false) {
                $isValid = false;
                $errorsByKey[$rule['key']] = $rule['message'];
            } elseif ($rule['pass'] === null) {
                // Indeterminate (HIBP fail-open / still checking). Never count
                // a null as passed — surface it so the client can render an
                // "in progress / unverified" state instead of a green check,
                // and so `isValid` doesn't claim success on an unconfirmed rule.
                $pendingKeys[] = $rule['key'];
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

        $clientPendingKeys = array_values(array_unique(
            array_map(fn(string $key) => $this->_clientKey($key), $pendingKeys),
        ));

        // Strength block — zxcvbn-php on every edition. Blocklist hits
        // force the meter to "weak" so the indicator stays consistent
        // with the rule list.
        $blocklistHit = isset($errorsByKey['common']);
        $strength = $plugin->getStrength()->compute(
            $password,
            $settings,
            $this->_resolveStrengthContext($request),
            $blocklistHit,
        );

        return $this->asJson([
            'isValid' => $isValid,
            'passed' => $isValid,
            'errorsByKey' => $clientErrorsByKey,
            'errors' => array_values($clientErrorsByKey),
            'pendingKeys' => $clientPendingKeys,
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

    /**
     * Resolves the policy IDs that scope the per-policy custom blocklist
     * (G6) for this request.
     *
     * Authenticated Enterprise requests resolve via `PolicyResolverService`
     * — the validator then sees global rows + the authenticated user's
     * applicable per-policy rows. Anonymous requests, Pro/Lite installs,
     * and authenticated requests where per-group policies are disabled
     * all return `null` (global only).
     *
     * Anonymous requests intentionally ignore any `groups[]` POST param
     * for blocklist scoping. Honoring it would let an attacker probe
     * which words a target group's policy has registered as custom by
     * varying the submitted group handle and observing the per-rule
     * pass/fail bits in the response.
     *
     * @param User $user the temp/identity user from `_buildTempUser`
     * @return int[]|null policy IDs to scope to, or null for global only
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolvePolicyIdsForRequest(User $user): ?array
    {
        $plugin = PasswordPolicy::$plugin;

        if (!$plugin->getIsEnterprise()) {
            return null;
        }

        if (!$plugin->getSettings()->enablePerGroupPolicies) {
            return null;
        }

        // Per-policy filter only when a real authenticated identity backs
        // the request. Anonymous "group preview" callers (whose temp user
        // has no id) drop through to null — global rows only.
        if ($user->id === null) {
            return null;
        }

        $policies = $plugin->getPolicies()->getPoliciesForGroupIds(
            array_map(fn($g) => (int)$g->id, $user->getGroups()),
        );

        return array_values(array_filter(array_map(
            fn($policy) => $policy->id !== null ? (int)$policy->id : null,
            $policies,
        )));
    }

    /**
     * Resolves the username + email context forwarded to the zxcvbn-php
     * strength engine.
     *
     * Authenticated requests pull username/email from the session identity
     * — never from POST — so an attacker can't influence the strength signal
     * by submitting a known username alongside a guessed password. Anonymous
     * requests get an empty context: the alternative (trusting POST values)
     * lets unauthenticated callers prime the user-input dictionary with
     * arbitrary strings and observe how that changes the strength score
     * for a known account.
     *
     * Values are length-clamped at 254 chars (RFC 5321 mailbox length cap)
     * defensively so a pathological username can't blow up zxcvbn's matchers.
     *
     * @param \craft\web\Request $request
     * @return array{username: string, email: string}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveStrengthContext(\craft\web\Request $request): array
    {
        /** @var User|null $currentUser */
        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser === null) {
            return ['username' => '', 'email' => ''];
        }

        return [
            'username' => substr((string)$currentUser->username, 0, 254),
            'email' => substr((string)$currentUser->email, 0, 254),
        ];
    }
}
