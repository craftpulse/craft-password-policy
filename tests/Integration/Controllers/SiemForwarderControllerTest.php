<?php
/**
 * Pest coverage for `SiemForwarderController::actionSave` across both
 * destination types. Pinned contracts:
 *
 *  - A syslog forwarder saves host + port + framing; an HTTP forwarder
 *    saves URL + auth type + credential + custom headers.
 *  - The credential is never rendered back into the form, so an empty
 *    `authToken` POST keeps the stored one instead of clearing it.
 *  - The editable-table `headers` POST shape becomes a name => value map,
 *    and a row with no name is dropped.
 *  - A save response never carries the decrypted credential.
 *  - Read-only mode (`allowAdminChanges = false`) blocks the save.
 *
 * Follows the controller-test setup in `WebhookEndpointControllerTest`:
 * console-bootstrap-friendly stubs for `request` and `user`, and
 * `runAction()` rather than a direct method call so `beforeAction()`'s
 * edition and permission gates fire in the real order.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\SiemForwarderController;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;

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

    // The forwarder surface is Enterprise-only.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->userStub->setIdentity(UserFactory::admin());

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_siem_forwarders}}')
        ->execute();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs a controller action through `Controller::runAction()` so
 * `beforeAction()` fires (CP request + edition gate + permission) in the
 * same order it would in a real HTTP request.
 */
function runSiemForwarderAction(string $actionId, array $params = []): mixed
{
    $controller = new SiemForwarderController('siem-forwarder', PasswordPolicy::$plugin);

    return $controller->runAction($actionId, $params);
}

/**
 * Returns the single forwarder row, straight from the DB.
 *
 * @return array<string, mixed>|null
 */
function siemForwarderRow(): ?array
{
    $row = (new Query())
        ->from('{{%passwordpolicy_siem_forwarders}}')
        ->orderBy(['id' => SORT_DESC])
        ->one();

    return is_array($row) ? $row : null;
}

// =============================================================================
// actionSave — syslog destination
// =============================================================================

it('saves a syslog forwarder with its framing choice', function() {
    $this->request->stubBodyParams = [
        'name' => 'Central rsyslog',
        'protocol' => 'syslog-tls',
        'host' => 'siem.example.test',
        'port' => '6514',
        'framing' => 'newline',
        'enabled' => '1',
    ];

    $response = runSiemForwarderAction('save');

    expect($response)->toBeInstanceOf(Response::class);

    $row = siemForwarderRow();

    expect($row)->not->toBeNull()
        ->and($row['protocol'])->toBe('syslog-tls')
        ->and($row['host'])->toBe('siem.example.test')
        ->and((int)$row['port'])->toBe(6514)
        ->and($row['framing'])->toBe('newline')
        // The HTTP half stays empty on a syslog row.
        ->and($row['url'])->toBeNull()
        ->and($row['authToken'])->toBeNull();
});

// =============================================================================
// actionSave — HTTP destination
// =============================================================================

it('saves an HTTP forwarder with credential and custom headers', function() {
    $this->request->stubBodyParams = [
        'name' => 'Collector',
        'protocol' => 'http',
        'url' => 'https://collector.example.test/ingest',
        'authType' => 'bearer',
        'authToken' => 'posted-token',
        'headers' => [
            ['name' => 'X-Env', 'value' => 'production'],
            // A row the operator added and never filled in.
            ['name' => '', 'value' => ''],
        ],
        'enabled' => '1',
    ];

    $response = runSiemForwarderAction('save');

    expect($response)->toBeInstanceOf(Response::class);

    $row = siemForwarderRow();

    expect($row)->not->toBeNull()
        ->and($row['protocol'])->toBe('http')
        ->and($row['url'])->toBe('https://collector.example.test/ingest')
        ->and($row['authType'])->toBe('bearer')
        // Ciphertext at rest, never the posted plaintext.
        ->and($row['authToken'])->not->toBe('posted-token')
        ->and($row['authToken'])->toMatch('/^[A-Za-z0-9+\/=_-]+$/')
        // The empty table row is dropped rather than saved as a header.
        // Decoded rather than compared as bytes: each engine formats its
        // JSON column its own way.
        ->and(json_decode((string)$row['headers'], true))->toBe(['X-Env' => 'production'])
        // The syslog half stays empty on an HTTP row.
        ->and($row['host'])->toBeNull()
        ->and($row['port'])->toBeNull();

    $loaded = PasswordPolicy::$plugin->getSiem()->getForwarderById((int)$row['id']);

    expect($loaded?->authToken)->toBe('posted-token')
        ->and($loaded?->headers)->toBe(['X-Env' => 'production']);
});

it('keeps the stored credential when the field is submitted empty', function() {
    $forwarder = new SiemForwarderModel();
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $forwarder->url = 'https://collector.example.test/ingest';
    $forwarder->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $forwarder->authToken = 'original-token';
    PasswordPolicy::$plugin->getSiem()->saveForwarder($forwarder);

    // The edit screen never renders the credential, so a save that doesn't
    // touch the field posts an empty string.
    $this->request->stubBodyParams = [
        'forwarderId' => (string)$forwarder->id,
        'name' => 'Renamed',
        'protocol' => 'http',
        'url' => 'https://collector.example.test/ingest',
        'authType' => 'bearer',
        'authToken' => '',
        'enabled' => '1',
    ];

    runSiemForwarderAction('save');

    $loaded = PasswordPolicy::$plugin->getSiem()->getForwarderById((int)$forwarder->id);

    expect($loaded?->name)->toBe('Renamed')
        ->and($loaded?->authToken)->toBe('original-token');
});

it('never returns the decrypted credential in the save response', function() {
    $this->request->stubBodyParams = [
        'protocol' => 'http',
        'url' => 'https://collector.example.test/ingest',
        'authType' => 'bearer',
        'authToken' => 'never-echo-me',
        'enabled' => '1',
    ];
    $this->request->stubAcceptsJson = true;

    $response = runSiemForwarderAction('save');

    expect(json_encode($response->data))->not->toContain('never-echo-me');
});

// =============================================================================
// actionSave — validation
// =============================================================================

it('rejects an HTTP forwarder with no URL', function() {
    $this->request->stubBodyParams = [
        'protocol' => 'http',
        'url' => '',
        'enabled' => '1',
    ];

    $response = runSiemForwarderAction('save');

    expect($response->getStatusCode())->toBeGreaterThanOrEqual(400)
        ->and(siemForwarderRow())->toBeNull();
});

it('rejects a plaintext http URL', function() {
    $this->request->stubBodyParams = [
        'protocol' => 'http',
        'url' => 'http://collector.example.test/ingest',
        'enabled' => '1',
    ];

    $response = runSiemForwarderAction('save');

    expect($response->getStatusCode())->toBeGreaterThanOrEqual(400)
        ->and(siemForwarderRow())->toBeNull();
});

it('rejects a custom header that collides with the auth type', function() {
    $this->request->stubBodyParams = [
        'protocol' => 'http',
        'url' => 'https://collector.example.test/ingest',
        'authType' => 'bearer',
        'authToken' => 'token',
        'headers' => [['name' => 'Authorization', 'value' => 'Splunk other']],
        'enabled' => '1',
    ];

    $response = runSiemForwarderAction('save');

    expect($response->getStatusCode())->toBeGreaterThanOrEqual(400)
        ->and(siemForwarderRow())->toBeNull();
});

// =============================================================================
// Edit screen — the content template the screen renders
// =============================================================================

/**
 * Renders the forwarder edit screen's content template. It's a content
 * template rather than a layout-extending one, so a console-bootstrapped
 * process can render it, which is what catches a macro called with the
 * wrong shape.
 */
function renderSiemForwarderEditScreen(SiemForwarderModel $forwarder, bool $readOnly = false): string
{
    $view = Craft::$app->getView();
    $oldMode = $view->getTemplateMode();
    $view->setTemplateMode($view::TEMPLATE_MODE_CP);

    try {
        return $view->renderTemplate('password-policy/_siem/_edit', [
            'forwarder' => $forwarder,
            'isNew' => $forwarder->id === null,
            'readOnly' => $readOnly,
        ]);
    } finally {
        $view->setTemplateMode($oldMode);
    }
}

it('renders the edit screen for a new forwarder with both destination groups', function() {
    $html = renderSiemForwarderEditScreen(new SiemForwarderModel());

    expect($html)->toContain('name="protocol"')
        ->and($html)->toContain('name="host"')
        ->and($html)->toContain('name="framing"')
        ->and($html)->toContain('name="authType"')
        ->and($html)->toContain('name="headers"')
        // `url` and `authToken` are autosuggest fields: their input is built
        // by a Vue init that `{% js %}` hands to the View rather than to this
        // string, so the rendered label is what proves the field is there.
        ->and($html)->toContain('Endpoint URL')
        ->and($html)->toContain('Credential')
        // Both groups are present; the toggle hides one of them.
        ->and($html)->toContain('pp-protocol-syslog-tls')
        ->and($html)->toContain('pp-protocol-http')
        // The syslog group is the visible one on a new forwarder.
        ->and($html)->toContain('pp-protocol-http hidden');
});

it('shows the HTTP group first on an HTTP forwarder', function() {
    $forwarder = new SiemForwarderModel();
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $forwarder->url = 'https://collector.example.test/ingest';

    $html = renderSiemForwarderEditScreen($forwarder);

    expect($html)->toContain('pp-protocol-syslog-tls hidden')
        ->and($html)->not->toContain('pp-protocol-http hidden');
});

it('never renders a stored credential back into the form', function() {
    $forwarder = new SiemForwarderModel();
    $forwarder->id = 1;
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $forwarder->url = 'https://collector.example.test/ingest';
    $forwarder->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $forwarder->authToken = 'stored-secret-value';

    $html = renderSiemForwarderEditScreen($forwarder);

    expect($html)->not->toContain('stored-secret-value')
        // But it does say a credential is on file, so an operator doesn't
        // read the empty field as "no token".
        ->and($html)->toContain('A token is stored.');
});

it('renders every field disabled in read-only mode', function() {
    $forwarder = new SiemForwarderModel();
    $forwarder->id = 1;
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $forwarder->url = 'https://collector.example.test/ingest';
    $forwarder->headers = ['X-Env' => 'production'];

    $html = renderSiemForwarderEditScreen($forwarder, readOnly: true);

    expect($html)->toContain('disabled')
        // The editable table renders static rather than offering an add row.
        ->and($html)->not->toContain('Add a header');
});

// =============================================================================
// Read-only mode
// =============================================================================

it('blocks the save when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->request->stubBodyParams = [
        'protocol' => 'http',
        'url' => 'https://collector.example.test/ingest',
        'enabled' => '1',
    ];

    expect(fn() => runSiemForwarderAction('save'))
        ->toThrow(ForbiddenHttpException::class);

    expect(siemForwarderRow())->toBeNull();
});
