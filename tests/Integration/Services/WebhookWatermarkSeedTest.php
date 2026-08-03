<?php
/**
 * Pest coverage for the dispatch watermark a NEW webhook endpoint starts on.
 *
 * `WebhookForwardJob` dispatches rows where `id > (lastDeliveredRowId ?? 0)`,
 * so an endpoint saved with a null cursor is owed every audit row ever written.
 * Three places state the opposite — `WebhookEndpointModel::$lastDeliveredRowId`'s
 * own docblock, and two paragraphs of `docs/user/features/webhooks.md` — and the
 * feature deliberately ships no backfill, on the grounds that handing a receiver
 * thousands of events at once gets the delivery rate-limited.
 *
 * The contradiction was unobservable while nothing enqueued the job. Adding the
 * `password-policy/webhook/run` sweep makes it observable on the first cron
 * tick, against the full retention window of the audit log, which is why the
 * cursor is now seeded at creation and pinned here.
 *
 * The Guzzle transport is mocked via `MockHandler` spliced through
 * `TestGuzzleConfig`, mirroring `WebhookServiceTest`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\AuditLogElement;
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
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
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
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts an audit-log row, bypassing the chain writer. Every audit row pairs
 * with a `craft_elements` row via `id`, so the element row is allocated first
 * to satisfy the foreign key.
 */
function makeSeedAuditRow(): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert(Table::ELEMENTS, [
            'type' => AuditLogElement::class,
            'enabled' => 1,
            'archived' => 0,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    $elementId = (int)Craft::$app->getDb()->getLastInsertID(Table::ELEMENTS);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', [
            'id' => $elementId,
            'event' => 'watermark_seed_fixture',
            'outcome' => 'success',
            'source' => 'admin',
            'rowHash' => str_repeat('a', 64),
            'previousHash' => str_repeat('0', 64),
            'forwardedAt' => null,
            'forwardAttempts' => 0,
            'dateCreated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    return $elementId;
}

/**
 * Saves a fresh endpoint through the service.
 */
function makeSeedEndpoint(?int $cursor = null): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = 'seed-fixture';
    $endpoint->url = 'https://hooks.example.test/audit';
    $endpoint->enabled = true;
    $endpoint->lastDeliveredRowId = $cursor;

    PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint);

    return $endpoint;
}

// =============================================================================
// A new endpoint starts from the newest row, not from the first
// =============================================================================

it('seeds a new endpoint cursor to the newest audit row', function() {
    makeSeedAuditRow();
    makeSeedAuditRow();
    $newest = makeSeedAuditRow();

    $endpoint = makeSeedEndpoint();

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

    expect($endpoint->lastDeliveredRowId)->toBe($newest)
        ->and((int)$record->lastDeliveredRowId)->toBe($newest);
});

it('leaves the cursor null when the audit log is empty', function() {
    $endpoint = makeSeedEndpoint();

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

    expect($endpoint->lastDeliveredRowId)->toBeNull()
        ->and($record->lastDeliveredRowId)->toBeNull();
});

it('honors an explicitly supplied cursor', function() {
    $first = makeSeedAuditRow();
    makeSeedAuditRow();

    $endpoint = makeSeedEndpoint(cursor: $first);

    expect($endpoint->lastDeliveredRowId)->toBe($first);
});

// =============================================================================
// A later save must not rewind an established cursor
// =============================================================================

it('does not reseed the cursor when an existing endpoint is saved again', function() {
    $first = makeSeedAuditRow();
    $endpoint = makeSeedEndpoint(cursor: $first);

    makeSeedAuditRow();
    $endpoint->name = 'renamed';
    $this->service->saveEndpoint($endpoint);

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

    expect((int)$record->lastDeliveredRowId)->toBe($first);
});

// =============================================================================
// The job honours the seed — no replay of pre-existing history
// =============================================================================

it('does not replay rows written before the endpoint existed', function() {
    makeSeedAuditRow();
    makeSeedAuditRow();

    $endpoint = makeSeedEndpoint();

    $afterCreation = makeSeedAuditRow();

    // Three responses queued for a fixture that must consume exactly one.
    for ($i = 0; $i < 3; $i++) {
        $this->mockHandler->append(new Response(200));
    }

    $job = new WebhookForwardJob();
    (new ReflectionClass($job))->getMethod('processItem')->invoke($job, $endpoint);

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

    expect((int)$record->lastDeliveredRowId)->toBe($afterCreation)
        ->and($this->mockHandler->count())->toBe(2);
});
