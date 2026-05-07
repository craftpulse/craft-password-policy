<?php
/**
 * Pest coverage for `WebhookService` — the G9 HMAC-signed webhook
 * forwarder. Pinned contracts:
 *
 *  - `dispatch()` constructs the canonical headers (Content-Type,
 *    X-PasswordPolicy-Timestamp, X-PasswordPolicy-Event-Id,
 *    X-PasswordPolicy-Signature) and signs the body with `secretCurrent`.
 *    The signature MUST verify against the bytes we sent on the wire
 *    when recomputed by the recipient.
 *  - Body bit-identical to `AuditLogService::canonicalize($row)`. SIEM
 *    and webhook consumers see the same byte sequence.
 *  - `dispatch()` returns true on a 2xx, false on 4xx/5xx/transport
 *    failure. NEVER throws.
 *  - `getActiveEndpoints()` excludes circuit-open endpoints inside the
 *    cooldown window; INCLUDES them past cooldown (half-open probe).
 *  - `rotateSecret()` moves current → previous, regenerates current,
 *    pins `secretRotatedAt`. Encrypted at rest verified by re-fetching
 *    the record + asserting the raw column is non-plaintext.
 *  - `sendTestEvent()` writes a `webhook_test` audit row + dispatches
 *    + returns the result shape the controller's AJAX response
 *    consumes.
 *  - Circuit breaker: increments on failure, opens at threshold,
 *    resets on success.
 *
 * The Guzzle transport is mocked via `MockHandler` spliced through
 * `TestGuzzleConfig`, mirroring `GuzzleHibpClientTest`'s pattern.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;
use craftpulse\passwordpolicy\services\AuditLogService;
use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getWebhook();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_webhook_endpoints}}')
        ->execute();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    Craft::$app->getCache()->flush();

    $this->mockHandler = new MockHandler();
    TestGuzzleConfig::setMockHandler($this->mockHandler);
});

afterEach(function() {
    TestGuzzleConfig::clear();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts an endpoint via the service so the model + record stay in
 * sync (encryption boundary handled correctly). Returns the persisted
 * model. The plaintext secret is preserved on the model surface for
 * test assertions.
 */
function makeEndpoint(array $overrides = []): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = $overrides['name'] ?? 'test';
    $endpoint->url = $overrides['url'] ?? 'https://hooks.example.test/audit';
    $endpoint->secretCurrent = $overrides['secretCurrent'] ?? 'fixture-secret-' . bin2hex(random_bytes(8));
    $endpoint->enabled = $overrides['enabled'] ?? true;
    $endpoint->eventClasses = $overrides['eventClasses'] ?? null;

    $saved = PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint);

    if (!$saved) {
        throw new RuntimeException('Failed to save fixture endpoint: ' . json_encode($endpoint->getErrors()));
    }

    return $endpoint;
}

/**
 * Back-dates an endpoint's `circuitOpenAt` so the cooldown window has
 * elapsed (endpoint enters half-open state).
 */
function expireWebhookCircuit(int $endpointId, int $secondsAgo = 600): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            ['circuitOpenAt' => Carbon::now('UTC')->subSeconds($secondsAgo)->format('Y-m-d H:i:s')],
            ['id' => $endpointId],
        )
        ->execute();
}

// =============================================================================
// dispatch() — header + signature contract
// =============================================================================

it('dispatches with the documented HMAC headers and verifiable signature', function() {
    $endpoint = makeEndpoint(['secretCurrent' => 'known-fixture-secret']);
    $row = [
        'id' => 1,
        'event' => 'webhook_test',
        'uid' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        'outcome' => 'success',
    ];
    $this->mockHandler->append(new Response(204));

    $result = $this->service->dispatch($row, $endpoint);

    expect($result)->toBeTrue();

    /** @var Request $sent */
    $sent = $this->mockHandler->getLastRequest();
    expect($sent)->not->toBeNull();
    expect($sent->getMethod())->toBe('POST');
    expect($sent->getHeaderLine('Content-Type'))->toBe('application/json');

    $timestamp = $sent->getHeaderLine('X-PasswordPolicy-Timestamp');
    expect($timestamp)->toMatch('/^\d+$/');

    $eventId = $sent->getHeaderLine('X-PasswordPolicy-Event-Id');
    expect($eventId)->toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');

    $signatureHeader = $sent->getHeaderLine('X-PasswordPolicy-Signature');
    expect($signatureHeader)->toStartWith('sha256=');

    $body = (string)$sent->getBody();
    expect($body)->toBe(AuditLogService::canonicalize($row));

    // Recompute the signature on the bytes we sent. Must match.
    $expected = 'sha256=' . hash_hmac(
        'sha256',
        $timestamp . '.' . $eventId . '.' . $body,
        'known-fixture-secret',
    );
    expect($signatureHeader)->toBe($expected);
});

it('returns true on a 200 / 204 success', function() {
    $endpoint = makeEndpoint();
    $this->mockHandler->append(new Response(200));

    $result = $this->service->dispatch(['id' => 1, 'uid' => 'x'], $endpoint);

    expect($result)->toBeTrue();
});

it('returns false on a 500 server error', function() {
    $endpoint = makeEndpoint();
    $this->mockHandler->append(new Response(500));

    $result = $this->service->dispatch(['id' => 1, 'uid' => 'x'], $endpoint);

    expect($result)->toBeFalse();
});

it('returns false on a 4xx client error without throwing', function() {
    $endpoint = makeEndpoint();
    $this->mockHandler->append(new Response(404));

    $result = $this->service->dispatch(['id' => 1, 'uid' => 'x'], $endpoint);

    expect($result)->toBeFalse();
});

// =============================================================================
// getActiveEndpoints
// =============================================================================

it('returns enabled, circuit-closed endpoints', function() {
    $endpoint = makeEndpoint();

    $active = $this->service->getActiveEndpoints();

    expect($active)->toHaveCount(1);
    expect($active[0]->id)->toBe($endpoint->id);
});

it('excludes disabled endpoints', function() {
    makeEndpoint(['enabled' => false]);

    $active = $this->service->getActiveEndpoints();

    expect($active)->toHaveCount(0);
});

it('excludes circuit-open endpoints inside the cooldown window', function() {
    $endpoint = makeEndpoint();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            [
                'circuitOpenAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'consecutiveFailures' => 5,
            ],
            ['id' => $endpoint->id],
        )
        ->execute();

    $active = $this->service->getActiveEndpoints();

    expect($active)->toHaveCount(0);
});

it('includes circuit-open endpoints past the cooldown (half-open probe)', function() {
    $endpoint = makeEndpoint();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            [
                'circuitOpenAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'consecutiveFailures' => 5,
            ],
            ['id' => $endpoint->id],
        )
        ->execute();

    expireWebhookCircuit((int)$endpoint->id, 600);

    $active = $this->service->getActiveEndpoints();

    expect($active)->toHaveCount(1);
});

// =============================================================================
// getEligibleEventClasses
// =============================================================================

it('returns the per-endpoint override when non-empty', function() {
    $endpoint = makeEndpoint(['eventClasses' => ['audit_log', 'notification_log']]);

    $classes = $this->service->getEligibleEventClasses($endpoint);

    expect($classes)->toBe(['audit_log', 'notification_log']);
});

it('falls back to the global setting when the override is null', function() {
    $endpoint = makeEndpoint();
    $endpoint->eventClasses = null;

    $classes = $this->service->getEligibleEventClasses($endpoint);

    expect($classes)->toBe($this->plugin->getSettings()->webhookForwardEventClasses);
});

// =============================================================================
// Encryption at rest
// =============================================================================

it('encrypts the secret at rest — DB column never holds plaintext', function() {
    $endpoint = makeEndpoint(['secretCurrent' => 'plaintext-secret-value']);

    $rawColumn = (new \craft\db\Query())
        ->select(['secretCurrent'])
        ->from('{{%passwordpolicy_webhook_endpoints}}')
        ->where(['id' => $endpoint->id])
        ->scalar();

    expect($rawColumn)->not->toBe('plaintext-secret-value');
    expect($rawColumn)->toMatch('/^[A-Za-z0-9+\/=_-]+$/');

    // Round-trip via the service hydrates back to plaintext on the
    // model surface.
    $reloaded = $this->service->getEndpointById((int)$endpoint->id);
    expect($reloaded?->secretCurrent)->toBe('plaintext-secret-value');
});

// =============================================================================
// rotateSecret
// =============================================================================

it('rotates: current → previous, generates new current, pins secretRotatedAt', function() {
    $endpoint = makeEndpoint(['secretCurrent' => 'old-secret']);

    $newSecret = $this->service->rotateSecret($endpoint);

    expect($newSecret)->not->toBe('old-secret');
    expect(strlen($newSecret))->toBeGreaterThanOrEqual(32);

    $reloaded = $this->service->getEndpointById((int)$endpoint->id);
    expect($reloaded?->secretCurrent)->toBe($newSecret);
    expect($reloaded?->secretPrevious)->toBe('old-secret');
    expect($reloaded?->secretRotatedAt)->not->toBeNull();
});

it('honors a caller-supplied secret on rotateSecret', function() {
    $endpoint = makeEndpoint(['secretCurrent' => 'old-secret']);

    $rotated = $this->service->rotateSecret($endpoint, 'caller-supplied-secret');

    expect($rotated)->toBe('caller-supplied-secret');

    $reloaded = $this->service->getEndpointById((int)$endpoint->id);
    expect($reloaded?->secretCurrent)->toBe('caller-supplied-secret');
});

// =============================================================================
// sendTestEvent
// =============================================================================

it('writes a webhook_test audit row and dispatches', function() {
    $previousAuditEnabled = $this->plugin->getSettings()->enableAuditLog;
    $this->plugin->getSettings()->enableAuditLog = true;

    try {
        $endpoint = makeEndpoint();
        $this->mockHandler->append(new Response(200));

        $result = $this->service->sendTestEvent($endpoint);

        expect($result)->toHaveKeys(['statusCode', 'duration', 'body', 'success']);
        expect($result['success'])->toBeTrue();
        expect($result['statusCode'])->toBe(200);

        $auditRow = (new \craft\db\Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['event' => 'webhook_test'])
            ->one();
        expect($auditRow)->not->toBeNull();
    } finally {
        $this->plugin->getSettings()->enableAuditLog = $previousAuditEnabled;
    }
});

// =============================================================================
// Circuit breaker
// =============================================================================

it('increments consecutiveFailures on a dispatch failure', function() {
    $endpoint = makeEndpoint();
    $this->mockHandler->append(new Response(500));

    $this->service->dispatch(['id' => 1, 'uid' => 'x'], $endpoint);

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($record)->not->toBeNull();
    expect((int)$record->consecutiveFailures)->toBe(1);
});

it('opens the circuit when consecutive failures cross the threshold', function() {
    $threshold = $this->plugin->getSettings()->webhookCircuitFailureThreshold;
    $endpoint = makeEndpoint();

    for ($i = 0; $i < $threshold; $i++) {
        $this->mockHandler->append(new Response(500));
        $this->service->dispatch(['id' => 1, 'uid' => 'x'], $endpoint);
        // Refresh the model for the service's "circuit already open?"
        // branch.
        $endpoint = $this->service->getEndpointById((int)$endpoint->id);
    }

    expect($endpoint->circuitOpenAt)->not->toBeNull();
    expect($endpoint->consecutiveFailures)->toBeGreaterThanOrEqual($threshold);
});

it('resets consecutive failures on a successful dispatch', function() {
    $endpoint = makeEndpoint();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            ['consecutiveFailures' => 3],
            ['id' => $endpoint->id],
        )
        ->execute();

    $endpoint = $this->service->getEndpointById((int)$endpoint->id);
    $this->mockHandler->append(new Response(200));

    $this->service->dispatch(['id' => 1, 'uid' => 'x'], $endpoint);

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect((int)$record->consecutiveFailures)->toBe(0);
});

// =============================================================================
// resetCircuit
// =============================================================================

it('clears circuitOpenAt and consecutiveFailures on resetCircuit', function() {
    $endpoint = makeEndpoint();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            [
                'circuitOpenAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'consecutiveFailures' => 7,
            ],
            ['id' => $endpoint->id],
        )
        ->execute();

    $reset = $this->service->resetCircuit((int)$endpoint->id);

    expect($reset)->toBeTrue();

    $refreshed = $this->service->getEndpointById((int)$endpoint->id);
    expect($refreshed?->circuitOpenAt)->toBeNull();
    expect($refreshed?->consecutiveFailures)->toBe(0);
});

// =============================================================================
// saveEndpoint + getEndpointById round-trip
// =============================================================================

it('persists a new endpoint and returns it via getEndpointById', function() {
    $model = new WebhookEndpointModel();
    $model->name = 'Compliance dashboard';
    $model->url = 'https://hooks.example.test/audit';
    $model->eventClasses = ['audit_log'];
    $model->enabled = true;

    $saved = $this->service->saveEndpoint($model);

    expect($saved)->toBeTrue();
    expect($model->id)->not->toBeNull();
    expect($model->uid)->not->toBeNull();
    // Auto-generated initial secret.
    expect($model->secretCurrent)->not->toBeNull();
    expect(strlen($model->secretCurrent))->toBeGreaterThanOrEqual(32);

    $loaded = $this->service->getEndpointById((int)$model->id);

    expect($loaded)->not->toBeNull();
    expect($loaded->name)->toBe('Compliance dashboard');
    expect($loaded->url)->toBe('https://hooks.example.test/audit');
    expect($loaded->eventClasses)->toBe(['audit_log']);
});

it('rejects an invalid endpoint via the model rules', function() {
    $model = new WebhookEndpointModel();
    $model->url = '';

    $saved = $this->service->saveEndpoint($model);

    expect($saved)->toBeFalse();
    expect($model->getErrors('url'))->not->toBeEmpty();
});

// =============================================================================
// listEndpoints + deleteEndpoint
// =============================================================================

it('lists every endpoint ordered by id', function() {
    $a = makeEndpoint(['name' => 'a']);
    $b = makeEndpoint(['name' => 'b']);

    $list = $this->service->listEndpoints();

    expect($list)->toHaveCount(2);
    expect($list[0]->id)->toBe($a->id);
    expect($list[1]->id)->toBe($b->id);
});

it('removes the endpoint row on delete', function() {
    $endpoint = makeEndpoint();

    $deleted = $this->service->deleteEndpoint((int)$endpoint->id);

    expect($deleted)->toBeTrue();
    expect($this->service->getEndpointById((int)$endpoint->id))->toBeNull();
});
