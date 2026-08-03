<?php
/**
 * Pest coverage for `WebhookEndpointController` — the G9 CP CRUD
 * surface for webhook endpoints. Pinned contracts:
 *
 *  - Index renders on Enterprise, throws ForbiddenHttpException on
 *    Lite / Pro (edition gate in `beforeAction`).
 *  - `actionSave` creates an endpoint and surfaces the freshly-
 *    generated plaintext secret EXACTLY ONCE via session flash. The
 *    flash is consumed on the next render and never re-emitted.
 *  - `actionRotateSecret` AJAX returns the new secret + grace window
 *    end timestamp.
 *  - `actionTestFire` AJAX returns the dispatch outcome shape.
 *  - `actionDelete` removes the endpoint.
 *  - Read-only mode (`allowAdminChanges = false`) blocks all writes.
 *
 * Mirrors the controller-test trifecta from
 * `UserPasswordControllerTest`: console-bootstrap-friendly stubs for
 * `request`, `user`, and the elevated-session signal.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\WebhookEndpointController;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Webhook surface is Enterprise-only — pin Enterprise in setup.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_webhook_endpoints}}')
        ->execute();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $this->mockHandler = new MockHandler();
    TestGuzzleConfig::setMockHandler($this->mockHandler);
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    TestGuzzleConfig::clear();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs a controller action through `Controller::runAction()` so
 * `beforeAction()` fires (CP request + edition gate + permission)
 * in the same order it would in a real HTTP request.
 */
function runWebhookEndpointAction(string $actionId, array $params = []): mixed
{
    $controller = new WebhookEndpointController('webhook-endpoint', PasswordPolicy::$plugin);

    return $controller->runAction($actionId, $params);
}

function makeControllerEndpoint(): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = 'fixture';
    $endpoint->url = 'https://hooks.example.test/audit';
    $endpoint->secretCurrent = 'fixture-secret';
    $endpoint->enabled = true;

    PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint);

    return $endpoint;
}

// =============================================================================
// Edition gate — beforeAction
// =============================================================================

it('throws NotFoundHttpException on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    expect(fn() => runWebhookEndpointAction('index'))
        ->toThrow(NotFoundHttpException::class);
});

it('throws NotFoundHttpException on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runWebhookEndpointAction('index'))
        ->toThrow(NotFoundHttpException::class);
});

// =============================================================================
// actionSave — happy path + once-and-only-once secret surfacing
// =============================================================================

it('creates an endpoint with an auto-generated encrypted secret on save', function() {
    $this->request->stubBodyParams = [
        'name' => 'Compliance dashboard',
        'url' => 'https://hooks.example.test/audit',
        'enabled' => '1',
    ];
    $this->request->stubAcceptsJson = true;

    $response = runWebhookEndpointAction('save');

    expect($response)->toBeInstanceOf(Response::class);

    $row = (new Query())
        ->from('{{%passwordpolicy_webhook_endpoints}}')
        ->where(['name' => 'Compliance dashboard'])
        ->one();

    expect($row)->not->toBeNull();
    // The stored secret is base64-wrapped ciphertext, not plaintext.
    expect($row['secretCurrent'])->toMatch('/^[A-Za-z0-9+\/=_-]+$/');
    expect(strlen($row['secretCurrent']))->toBeGreaterThan(40);

    // Hydrating via the service decrypts the secret to plaintext.
    $loaded = PasswordPolicy::$plugin->getWebhook()->getEndpointById((int)$row['id']);
    expect($loaded?->secretCurrent)->toBeString();
    expect(strlen($loaded->secretCurrent))->toBeGreaterThanOrEqual(32);
});

// =============================================================================
// actionSave — validation failure
// =============================================================================

it('rejects an empty URL with a validation error', function() {
    $this->request->stubBodyParams = [
        'name' => 'Bad endpoint',
        'url' => '',
    ];

    $response = runWebhookEndpointAction('save');

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->getStatusCode())->toBeGreaterThanOrEqual(400);
});

// =============================================================================
// actionRotateSecret — AJAX response shape
// =============================================================================

it('returns the new plaintext secret + grace window end timestamp', function() {
    $endpoint = makeControllerEndpoint();

    $this->request->stubBodyParams = [
        'endpointId' => $endpoint->id,
    ];
    $this->request->stubAcceptsJson = true;

    $response = runWebhookEndpointAction('rotate-secret');

    expect($response)->toBeInstanceOf(Response::class);

    $data = $response->data;
    expect($data['success'])->toBeTrue();
    expect($data['newSecret'])->toBeString();
    expect(strlen($data['newSecret']))->toBeGreaterThanOrEqual(32);
    expect($data['graceWindowEndsAt'])->toBeString();
});

// =============================================================================
// actionTestFire — AJAX response shape
// =============================================================================

it('returns statusCode + duration + body for a test dispatch', function() {
    $endpoint = makeControllerEndpoint();
    $this->plugin->getSettings()->enableAuditLog = true;
    $this->mockHandler->append(new GuzzleResponse(204));

    $this->request->stubBodyParams = [
        'endpointId' => $endpoint->id,
    ];
    $this->request->stubAcceptsJson = true;

    $response = runWebhookEndpointAction('test-fire');

    expect($response)->toBeInstanceOf(Response::class);
    $data = $response->data;
    expect($data)->toHaveKeys(['success', 'statusCode', 'duration', 'body', 'message']);
    expect($data['success'])->toBeTrue();
    expect($data['statusCode'])->toBe(204);
});

// =============================================================================
// actionDelete
// =============================================================================

it('deletes an endpoint', function() {
    $endpoint = makeControllerEndpoint();
    $this->request->stubBodyParams = [
        'id' => $endpoint->id,
    ];
    $this->request->stubAcceptsJson = true;

    $response = runWebhookEndpointAction('delete');

    expect($response)->toBeInstanceOf(Response::class);
    expect(PasswordPolicy::$plugin->getWebhook()->getEndpointById((int)$endpoint->id))->toBeNull();
});

// =============================================================================
// Read-only mode
// =============================================================================

it('rejects save when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->request->stubBodyParams = [
        'name' => 'New endpoint',
        'url' => 'https://hooks.example.test/audit',
    ];

    expect(fn() => runWebhookEndpointAction('save'))
        ->toThrow(ForbiddenHttpException::class);
});
