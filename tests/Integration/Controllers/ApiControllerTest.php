<?php
/**
 * Pest coverage for `ApiController` — the Feature 2 read-only REST surface
 * (Enterprise). Pinned contracts:
 *
 *  - Edition gate: Pro / Lite → ForbiddenHttpException in `beforeAction`.
 *  - `apiEnabled` off → 404 (endpoint doesn't exist for this install).
 *  - No / malformed / unknown / expired token → uniform 401.
 *  - Over the per-token rate limit → 429 with `Retry-After`.
 *  - Valid token → 200 with the documented JSON shape for each endpoint.
 *  - `tokenHash` never appears in any response body.
 *
 * The tests stand up a web-shaped request via `WebRequestStub` (so the
 * controller's GET / header reads work) plus a `craft\web\Response`
 * component (so `asJson()` + the 401/404/429 status writes have somewhere
 * to land), mirroring the console-bootstrap CP-test pattern.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\controllers\ApiController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalApiEnabled = $this->settings->apiEnabled;
    $this->originalSystemLive = Craft::$app->getConfig()->getGeneral()->isSystemLive;

    // Site-request controllers run Craft's "is the system live?" gate in
    // parent::beforeAction(); pin live so the anonymous API surface isn't
    // 503'd by the console-bootstrapped test environment.
    Craft::$app->getConfig()->getGeneral()->isSystemLive = true;

    $this->request = new WebRequestStub();
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // REST surface is Enterprise-only — pin Enterprise + apiEnabled in setup.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->apiEnabled = true;

    Craft::$app->getDb()->createCommand()->delete('{{%passwordpolicy_api_tokens}}')->execute();
    Craft::$app->getCache()->flush();

    // Issue a fixture token; capture the plaintext for the Bearer header.
    $issued = $this->plugin->getApiTokens()->issue('pest-fixture');
    $this->token = $issued['token'];
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    $this->settings->apiEnabled = $this->originalApiEnabled;
    Craft::$app->getConfig()->getGeneral()->isSystemLive = $this->originalSystemLive;
});

// =============================================================================
// Helpers
// =============================================================================

function setBearer(string $token): void
{
    /** @var WebRequestStub $request */
    $request = Craft::$app->getRequest();
    $request->stubHeaders = ['Authorization' => 'Bearer ' . $token];
}

/**
 * Runs an ApiController action through runAction() so beforeAction()
 * fires the full gate chain. Returns the Response Craft would emit
 * (the action Response, or the global response when beforeAction
 * short-circuited with false).
 */
function runApiAction(string $actionId, array $params = []): Response
{
    $controller = new ApiController('api', PasswordPolicy::$plugin);
    $result = $controller->runAction($actionId, $params);

    if ($result instanceof Response) {
        return $result;
    }

    /** @var Response $response */
    $response = Craft::$app->getResponse();

    return $response;
}

// =============================================================================
// Edition gate
// =============================================================================

it('throws ForbiddenHttpException on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    setBearer($this->token);

    expect(fn() => runApiAction('audit'))->toThrow(ForbiddenHttpException::class);
});

it('throws ForbiddenHttpException on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    setBearer($this->token);

    expect(fn() => runApiAction('audit'))->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// apiEnabled toggle
// =============================================================================

it('returns 404 when apiEnabled is off', function() {
    $this->settings->apiEnabled = false;
    setBearer($this->token);

    $response = runApiAction('audit');

    expect($response->getStatusCode())->toBe(404);
});

// =============================================================================
// Token auth — uniform 401
// =============================================================================

it('returns 401 with no Authorization header', function() {
    $this->request->stubHeaders = [];

    $response = runApiAction('audit');

    expect($response->getStatusCode())->toBe(401);
});

it('returns 401 with a malformed Authorization header', function() {
    $this->request->stubHeaders = ['Authorization' => 'NotBearer xyz'];

    $response = runApiAction('audit');

    expect($response->getStatusCode())->toBe(401);
});

it('returns 401 with an unknown bearer token', function() {
    setBearer('totally-unknown-token-value');

    $response = runApiAction('audit');

    expect($response->getStatusCode())->toBe(401);
});

it('returns 401 with an expired bearer token', function() {
    $expired = $this->plugin->getApiTokens()->issue(
        'expired',
        null,
        \Carbon\Carbon::now('UTC')->subDay()->toDateTime(),
    );
    setBearer($expired['token']);

    $response = runApiAction('audit');

    expect($response->getStatusCode())->toBe(401);
});

// =============================================================================
// Rate limit
// =============================================================================

it('returns 429 with Retry-After once the per-token limit is exceeded', function() {
    setBearer($this->token);

    // Burn the whole window, then one more.
    for ($i = 0; $i < ApiController::RATE_LIMIT; $i++) {
        $ok = runApiAction('audit');
        expect($ok->getStatusCode())->toBe(200);
    }

    $overLimit = runApiAction('audit');

    expect($overLimit->getStatusCode())->toBe(429)
        ->and($overLimit->getHeaders()->get('Retry-After'))->not->toBeNull();
});

// =============================================================================
// audit endpoint — 200 shape
// =============================================================================

it('returns the paginated audit shape on a valid request', function() {
    setBearer($this->token);

    $response = runApiAction('audit');

    expect($response->getStatusCode())->toBe(200);

    $data = $response->data;

    expect($data)->toHaveKey('total')
        ->and($data)->toHaveKey('limit')
        ->and($data)->toHaveKey('offset')
        ->and($data)->toHaveKey('rows')
        ->and($data['rows'])->toBeArray();
});

it('clamps the audit limit to the service maximum', function() {
    setBearer($this->token);
    $this->request->stubQueryParams = ['limit' => 99999];

    $response = runApiAction('audit');

    expect($response->data['limit'])
        ->toBe(\craftpulse\passwordpolicy\services\AuditLogService::MAX_API_QUERY_LIMIT);
});

it('never leaks tokenHash, rowHash, or chain internals in the audit response', function() {
    setBearer($this->token);

    $response = runApiAction('audit');
    $json = json_encode($response->data);

    expect($json)->not->toContain('tokenHash')
        ->and($json)->not->toContain('rowHash')
        ->and($json)->not->toContain('previousHash')
        ->and($json)->not->toContain('ipHash')
        ->and($json)->not->toContain(hash('sha256', $this->token));
});

// =============================================================================
// password-status endpoint — 200 shape
// =============================================================================

it('returns the password-status flag shape for a real user UID', function() {
    $user = UserFactory::admin();
    setBearer($this->token);

    $response = runApiAction('password-status', ['uid' => $user->uid]);

    expect($response->getStatusCode())->toBe(200);

    $data = $response->data;

    expect($data)->toHaveKey('userUid')
        ->and($data['userUid'])->toBe($user->uid)
        ->and($data)->toHaveKey('status')
        ->and($data)->toHaveKey('expired')
        ->and($data)->toHaveKey('breached')
        ->and($data)->toHaveKey('resetRequired')
        ->and($data)->toHaveKey('lastChange');
});

it('returns 404 for an unknown user UID on password-status', function() {
    setBearer($this->token);

    $response = runApiAction('password-status', ['uid' => 'nonexistent-uid-0000']);

    expect($response->getStatusCode())->toBe(404);
});

// =============================================================================
// policy resolve endpoint — 200 shape, no secrets
// =============================================================================

it('returns the resolved policy shape for a real user UID', function() {
    $user = UserFactory::admin();
    setBearer($this->token);
    $this->request->stubQueryParams = ['userUid' => $user->uid];

    $response = runApiAction('resolve-policy');

    expect($response->getStatusCode())->toBe(200);

    $data = $response->data;

    expect($data)->toHaveKey('userUid')
        ->and($data)->toHaveKey('policy')
        ->and($data['policy'])->toHaveKey('minLength')
        ->and($data['policy'])->toHaveKey('requireMixedCase')
        ->and($data['policy'])->toHaveKey('passwordHistoryCount');
});

it('omits secrets from the resolved policy response', function() {
    $user = UserFactory::admin();
    setBearer($this->token);
    $this->request->stubQueryParams = ['userUid' => $user->uid];

    $response = runApiAction('resolve-policy');
    $json = json_encode($response->data);

    expect($json)->not->toContain('auditPiiKey')
        ->and($json)->not->toContain('siemAuthToken')
        ->and($json)->not->toContain('secretCurrent')
        ->and($json)->not->toContain('webhooks');
});

it('returns 400 when userUid is missing on resolve-policy', function() {
    setBearer($this->token);
    $this->request->stubQueryParams = [];

    $response = runApiAction('resolve-policy');

    expect($response->getStatusCode())->toBe(400);
});
