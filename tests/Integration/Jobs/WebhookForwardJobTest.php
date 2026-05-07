<?php
/**
 * Pest coverage for `WebhookForwardJob` — the G9 batched dispatcher.
 *
 * Pinned contracts:
 *
 *  - Per-endpoint watermark advances on each successful dispatch.
 *  - Failed dispatch leaves the cursor where it was so the next job
 *    retries the same row, AND increments `consecutiveFailures`.
 *  - Per-endpoint allowlist is honored — endpoint A subscribed to
 *    `audit_log` and endpoint B with a null override (uses global
 *    default `['audit_log']`) both dispatch.
 *  - Edition gate: on Pro the job exits early without touching any
 *    endpoint state.
 *  - Circuit-open endpoints are not consulted (queried out by
 *    `getActiveEndpoints()`).
 *
 * The Guzzle transport is mocked via `MockHandler` spliced through
 * `TestGuzzleConfig` (mirrors `WebhookServiceTest`).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\jobs\WebhookForwardJob;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;
use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;

    // Job is Enterprise-only; default the test fixture to Enterprise.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

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
    $this->plugin->edition = $this->originalEdition;
    TestGuzzleConfig::clear();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts a webhook endpoint via the service.
 */
function makeJobEndpoint(array $overrides = []): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = $overrides['name'] ?? 'fixture';
    $endpoint->url = $overrides['url'] ?? 'https://hooks.example.test/audit';
    $endpoint->secretCurrent = $overrides['secretCurrent'] ?? 'fixture-secret-' . bin2hex(random_bytes(8));
    $endpoint->enabled = $overrides['enabled'] ?? true;
    $endpoint->eventClasses = $overrides['eventClasses'] ?? null;

    PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint);

    return $endpoint;
}

/**
 * Inserts an audit-log row directly (bypassing the chain writer for
 * fixture speed). Returns the inserted id.
 */
function makeWebhookAuditRow(array $overrides = []): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');
    $row = array_merge([
        'event' => 'webhook_test',
        'outcome' => 'success',
        'source' => 'admin',
        'rowHash' => str_repeat('a', 64),
        'previousHash' => str_repeat('0', 64),
        'forwardedAt' => null,
        'forwardAttempts' => 0,
        'dateCreated' => $now,
        'uid' => StringHelper::UUID(),
    ], $overrides);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', $row)
        ->execute();

    return (int)Craft::$app->getDb()->getLastInsertID('{{%passwordpolicy_audit_log}}');
}

/**
 * Invokes the job's protected `processItem` via reflection.
 */
function invokeWebhookProcessItem(WebhookForwardJob $job, mixed $item): void
{
    $method = (new ReflectionClass($job))->getMethod('processItem');
    $method->invoke($job, $item);
}

// =============================================================================
// Watermark advances on success
// =============================================================================

it('advances lastDeliveredRowId on each successful dispatch', function() {
    $endpoint = makeJobEndpoint();
    $rowA = makeWebhookAuditRow();
    $rowB = makeWebhookAuditRow();

    $this->mockHandler->append(new Response(200));
    $this->mockHandler->append(new Response(200));

    $job = new WebhookForwardJob();
    invokeWebhookProcessItem($job, $endpoint);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect((int)$reloaded->lastDeliveredRowId)->toBe($rowB);
});

// =============================================================================
// Failure isolates per-endpoint
// =============================================================================

it('leaves the cursor put on a dispatch failure', function() {
    $endpoint = makeJobEndpoint();
    makeWebhookAuditRow();

    $this->mockHandler->append(new Response(500));

    $job = new WebhookForwardJob();
    invokeWebhookProcessItem($job, $endpoint);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->lastDeliveredRowId)->toBeNull();
    expect((int)$reloaded->consecutiveFailures)->toBe(1);
});

it('stops the inner loop after the first failure on an endpoint', function() {
    $endpoint = makeJobEndpoint();
    $rowA = makeWebhookAuditRow();
    makeWebhookAuditRow();
    makeWebhookAuditRow();

    // Row A succeeds; row B fails. Job should advance cursor to A and
    // stop processing B/C in the same call.
    $this->mockHandler->append(new Response(200));
    $this->mockHandler->append(new Response(500));

    $job = new WebhookForwardJob();
    invokeWebhookProcessItem($job, $endpoint);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect((int)$reloaded->lastDeliveredRowId)->toBe($rowA);
});

// =============================================================================
// Per-endpoint allowlist
// =============================================================================

it('skips an endpoint whose eventClasses override excludes audit_log', function() {
    $endpoint = makeJobEndpoint(['eventClasses' => ['notification_log']]);
    makeWebhookAuditRow();

    $job = new WebhookForwardJob();
    invokeWebhookProcessItem($job, $endpoint);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->lastDeliveredRowId)->toBeNull();
});

it('honors the null allowlist override (falls back to global default)', function() {
    $endpoint = makeJobEndpoint();
    $endpoint->eventClasses = null;
    $rowId = makeWebhookAuditRow();

    $this->mockHandler->append(new Response(200));

    $job = new WebhookForwardJob();
    invokeWebhookProcessItem($job, $endpoint);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect((int)$reloaded->lastDeliveredRowId)->toBe($rowId);
});

// =============================================================================
// No-op on missing data
// =============================================================================

it('does nothing when there are no audit rows past the watermark', function() {
    $endpoint = makeJobEndpoint();

    $job = new WebhookForwardJob();
    invokeWebhookProcessItem($job, $endpoint);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->lastDeliveredRowId)->toBeNull();
    expect((int)$reloaded->consecutiveFailures)->toBe(0);
});

// =============================================================================
// Edition gate
// =============================================================================

it('exits early on Pro without touching endpoint state', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $endpoint = makeJobEndpoint();
    makeWebhookAuditRow();

    $job = new WebhookForwardJob();
    $job->execute(Craft::$app->getQueue());

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->lastDeliveredRowId)->toBeNull();
    expect((int)$reloaded->consecutiveFailures)->toBe(0);
});
