<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Craft;
use craft\elements\User;
use craft\web\Controller;
use craftpulse\passwordpolicy\models\ApiTokenModel;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\base\InvalidConfigException;
use yii\mutex\Mutex;
use yii\web\Response;

/**
 * Class ApiController
 *
 * The Feature 2 read-only REST surface (Enterprise). Three GET endpoints
 * under `/v1/`:
 *
 *  - `GET password-policy/api/v1/users/<uid>/password-status` — expiry /
 *    breach / reset-required / last-change flags for a user (by UID).
 *  - `GET password-policy/api/v1/policy/resolve?userUid=<uid>` — the
 *    resolved (per-group-aware) policy for a user. No secrets.
 *  - `GET password-policy/api/v1/audit?from=&to=&limit=&offset=` — a
 *    redacted, paginated slice of the audit log.
 *
 * **Auth.** Bearer token in the `Authorization` header
 * (`Authorization: Bearer <token>`). `$allowAnonymous = ['*']` — session
 * auth is replaced by token auth, so the CP session-cookie path is
 * irrelevant. CSRF is NOT disabled and does NOT need to be: every action
 * is a GET, and Craft only validates CSRF on unsafe methods.
 *
 * **Edition gate.** Below Enterprise the API answers with the same uniform
 * JSON 404 as an install with `apiEnabled` off: the endpoint does not exist
 * for that install, and the hide-not-badge doctrine keeps the response from
 * advertising an edition upgrade. Defense in depth: the CP token manager (the
 * only writer) is also Enterprise-gated, so a sub-edition install has no
 * tokens to present.
 *
 * **Rate limit.** Per-token fixed-window counter (60 req/min) in Craft's
 * cache, incremented under a per-token mutex so concurrent requests can't
 * race past the cap. Over the limit → 429 with a `Retry-After` header.
 *
 * **Uniform 401.** A missing, malformed, unknown, or expired token all
 * resolve to the same 401 body — no existence oracle.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ApiController extends Controller
{
    // Const Properties
    // =========================================================================

    /**
     * @var int requests allowed per token per fixed window.
     */
    public const RATE_LIMIT = 60;

    /**
     * @var int the fixed-window length, in seconds.
     */
    public const RATE_WINDOW_SECONDS = 60;

    /**
     * @var string cache-key prefix for the per-token request counter. The
     *     token HASH (never the plaintext) is appended so the key can't leak
     *     the secret if the cache backend is inspected.
     */
    public const RATE_CACHE_PREFIX = 'pp:api-rate:';

    // Public Properties
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Token auth replaces session auth, so every endpoint is listed
     * explicitly here (never a blanket `true`/`['*']` — the project rule
     * requires named action IDs). The per-action Bearer-token check in
     * {@see beforeAction()} is the real gate. CSRF is untouched: all
     * actions are GET, and Craft only validates CSRF on unsafe methods.
     *
     * @var array<int, string>|bool|int
     */
    protected array|bool|int $allowAnonymous = [
        'password-status',
        'resolve-policy',
        'audit',
    ];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Gate order: site request → Enterprise edition → `apiEnabled` → Bearer
     * token resolve → per-token rate limit. The first failing gate
     * short-circuits with the appropriate status code.
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        // Skip Craft's CSRF/site machinery cleanly for these token-authed
        // GET endpoints; we run our own auth below.
        if (!parent::beforeAction($action)) {
            return false;
        }

        // Below Enterprise the API doesn't exist for this install, so it
        // answers exactly like a disabled API: a uniform JSON 404, no
        // existence oracle and no edition-shaped error body.
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            $this->_send404();

            return false;
        }

        // `apiEnabled` off → the endpoint doesn't exist for this install.
        if (!PasswordPolicy::$plugin->getSettings()->apiEnabled) {
            $this->_send404();

            return false;
        }

        $token = $this->_resolveBearerToken();

        if ($token === null) {
            $this->_send401();

            return false;
        }

        if (!$this->_passesRateLimit($token)) {
            return false;
        }

        return true;
    }

    /**
     * `GET password-policy/api/v1/audit` — redacted, paginated audit-log
     * slice. Accepts `from`, `to`, `limit`, `offset` query params.
     *
     * @return Response
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionAudit(): Response
    {
        $request = Craft::$app->getRequest();

        $from = $request->getQueryParam('from');
        $to = $request->getQueryParam('to');
        $limit = (int)$request->getQueryParam('limit', 50);
        $offset = (int)$request->getQueryParam('offset', 0);

        $result = PasswordPolicy::$plugin->getAuditLog()->queryEvents(
            from: is_string($from) ? $from : null,
            to: is_string($to) ? $to : null,
            limit: $limit,
            offset: $offset,
        );

        return $this->asJson($result);
    }

    /**
     * `GET password-policy/api/v1/users/<uid>/password-status` — discrete
     * password-status flags for the user identified by `uid`.
     *
     * @param string $uid the user's element UID
     * @return Response
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionPasswordStatus(string $uid): Response
    {
        $user = $this->_userByUid($uid);

        if ($user === null) {
            return $this->asJson(['error' => 'User not found.'])
                ->setStatusCode(404);
        }

        $flags = PasswordPolicy::$plugin->getUserIndex()->getStatusFlagsForUser($user);

        return $this->asJson([
            'userUid' => $user->uid,
            'userId' => (int)$user->id,
        ] + $flags);
    }

    /**
     * `GET password-policy/api/v1/policy/resolve?userUid=<uid>` — the
     * resolved (per-group-aware) policy for the user. Emits only non-secret
     * policy fields.
     *
     * @return Response
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionResolvePolicy(): Response
    {
        $uid = (string)Craft::$app->getRequest()->getQueryParam('userUid', '');

        if ($uid === '') {
            return $this->asJson(['error' => 'Missing required query param `userUid`.'])
                ->setStatusCode(400);
        }

        $user = $this->_userByUid($uid);

        if ($user === null) {
            return $this->asJson(['error' => 'User not found.'])
                ->setStatusCode(404);
        }

        $resolved = PasswordPolicy::$plugin->getPolicyResolver()->resolveForUser($user);

        return $this->asJson([
            'userUid' => $user->uid,
            'userId' => (int)$user->id,
            'policy' => $this->_serializePolicy($resolved),
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Increments the per-token fixed-window counter under a per-token mutex
     * and returns whether the request is within the cap. On the first
     * request of a window the counter is seeded with the window TTL so it
     * self-expires. Over the cap → emits a 429 with `Retry-After` and
     * returns false.
     *
     * Mutex-guarded so two concurrent requests can't both read N, both
     * write N+1, and slip a request past the limit. If the mutex can't be
     * acquired (busy), fail-closed by treating the request as rate-limited
     * rather than letting it bypass the counter.
     *
     * @param ApiTokenModel $token
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _passesRateLimit(ApiTokenModel $token): bool
    {
        $cache = Craft::$app->getCache();
        $key = self::RATE_CACHE_PREFIX . $this->_tokenCacheDiscriminator($token);

        /** @var Mutex $mutex */
        $mutex = Craft::$app->getMutex();
        $lockName = 'pp:api-rate-lock:' . $this->_tokenCacheDiscriminator($token);

        if (!$mutex->acquire($lockName, 2)) {
            $this->_send429(self::RATE_WINDOW_SECONDS);

            return false;
        }

        try {
            $count = (int)$cache->get($key);
            $count++;

            $cache->set($key, $count, self::RATE_WINDOW_SECONDS);
        } finally {
            $mutex->release($lockName);
        }

        if ($count > self::RATE_LIMIT) {
            $this->_send429(self::RATE_WINDOW_SECONDS);

            return false;
        }

        return true;
    }

    /**
     * Reads + validates the Bearer token from the `Authorization` header.
     * Returns the resolved model, or null for a missing / malformed /
     * unknown / expired token (all uniform — no existence oracle).
     *
     * @return ApiTokenModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveBearerToken(): ?ApiTokenModel
    {
        $header = (string)Craft::$app->getRequest()->getHeaders()->get('Authorization', '');

        if (!preg_match('/^Bearer\s+(\S+)$/', trim($header), $matches)) {
            return null;
        }

        return PasswordPolicy::$plugin->getApiTokens()->findByToken($matches[1]);
    }

    /**
     * Serialises a resolved policy {@see SettingsModel} into a non-secret
     * field set for the `policy/resolve` endpoint. Explicit allowlist — no
     * SIEM/webhook/PII secrets, no infrastructure config, just the password
     * rules a consumer would enforce client-side.
     *
     * @param SettingsModel $settings
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _serializePolicy(SettingsModel $settings): array
    {
        return [
            'minLength' => $settings->minLength,
            'maxLength' => $settings->maxLength,
            'requireMixedCase' => $settings->cases,
            'requireNumbers' => $settings->numbers,
            'requireSymbols' => $settings->symbols,
            'checkCommonPasswords' => $settings->checkCommonPasswords,
            'hibp' => $settings->hibp,
            'passwordHistoryCount' => $settings->passwordHistoryCount,
            'minChangeIntervalHours' => $settings->minChangeIntervalHours,
            'expiryAmount' => $settings->expiryAmount,
            'expiryPeriod' => $settings->expiryPeriod,
        ];
    }

    /**
     * Returns a per-token cache/mutex discriminator. Uses the token id —
     * never the plaintext or the full hash — so the cache key carries no
     * recoverable secret.
     *
     * @param ApiTokenModel $token
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _tokenCacheDiscriminator(ApiTokenModel $token): string
    {
        return (string)$token->id;
    }

    /**
     * Resolves a User element by UID across all sites, or null when absent.
     *
     * @param string $uid
     * @return User|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _userByUid(string $uid): ?User
    {
        if ($uid === '') {
            return null;
        }

        return User::find()
            ->uid($uid)
            ->status(null)
            ->site('*')
            ->unique()
            ->one();
    }

    /**
     * Emits a uniform 404 JSON body (used when `apiEnabled` is off).
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _send404(): void
    {
        Craft::$app->getResponse()->setStatusCode(404);
        Craft::$app->getResponse()->format = Response::FORMAT_JSON;
        Craft::$app->getResponse()->data = ['error' => 'Not found.'];
    }

    /**
     * Emits a uniform 401 JSON body (missing / malformed / unknown /
     * expired token — all identical, no existence oracle).
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _send401(): void
    {
        Craft::$app->getResponse()->setStatusCode(401);
        Craft::$app->getResponse()->format = Response::FORMAT_JSON;
        Craft::$app->getResponse()->data = ['error' => 'Unauthorized.'];
    }

    /**
     * Emits a 429 JSON body with a `Retry-After` header.
     *
     * @param int $retryAfter seconds until the window resets
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _send429(int $retryAfter): void
    {
        $response = Craft::$app->getResponse();
        $response->setStatusCode(429);
        $response->getHeaders()->set('Retry-After', (string)$retryAfter);
        $response->format = Response::FORMAT_JSON;
        $response->data = ['error' => 'Rate limit exceeded.'];
    }
}
