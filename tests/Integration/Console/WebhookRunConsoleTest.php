<?php
/**
 * Pest coverage for the console `WebhookController::actionRun` — the trigger
 * that enqueues the Enterprise webhook delivery sweep.
 *
 * This file exists because the sweep had no trigger at all. `WebhookForwardJob`
 * shipped with a batcher, per-endpoint watermarks, and job-level coverage, and
 * nothing in `src/` ever pushed it: on a real Enterprise install no webhook was
 * ever delivered. A test asserting only the command's exit code would have
 * passed against that same void, so the assertions here are against a CAPTURED
 * QUEUE and, in the last test, against the cursor the captured job actually
 * advances.
 *
 * `CapturingQueue` is installed as the app's `queue` component so
 * `craft\helpers\Queue::push()` lands in it, and it captures at
 * `pushMessage()` — below the serializer — so what comes back out survived a
 * real serialize/unserialize round trip.
 *
 * The Guzzle transport is mocked via `MockHandler` spliced through
 * `TestGuzzleConfig`, so the end-to-end test drives the real `WebhookService`
 * rather than a stub.
 *
 * Pins:
 *
 *  - The command pushes a `WebhookForwardJob`, not merely returns
 *    `ExitCode::OK`.
 *  - The pushed job, run as a campaign, delivers pending audit rows and
 *    advances the endpoint's `lastDeliveredRowId`.
 *  - A sub-Enterprise install fails visibly (non-zero exit, stderr message)
 *    and pushes nothing.
 *  - With no active endpoint the command enqueues nothing rather than filling
 *    the queue table with no-op jobs on every cron tick.
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
use craftpulse\passwordpolicy\console\controllers\WebhookController;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\jobs\WebhookForwardJob;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;
use craftpulse\passwordpolicy\tests\Support\CapturingQueue;
use craftpulse\passwordpolicy\tests\Support\CapturingWebhookController;
use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use yii\console\ExitCode;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_webhook_endpoints}}')
        ->execute();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    Craft::$app->getCache()->flush();

    // `Queue::push()` resolves the app's `queue` component, so swapping it is
    // what makes the enqueue observable.
    $this->originalQueue = Craft::$app->getQueue();
    $this->queue = new CapturingQueue();
    Craft::$app->set('queue', $this->queue);

    $this->mockHandler = new MockHandler();
    TestGuzzleConfig::setMockHandler($this->mockHandler);
});

afterEach(function() {
    Craft::$app->set('queue', $this->originalQueue);
    TestGuzzleConfig::clear();
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

function newWebhookRunner(): CapturingWebhookController
{
    return new CapturingWebhookController('webhook', PasswordPolicy::$plugin);
}

/**
 * Inserts a webhook endpoint via the service.
 */
function makeSweepEndpoint(): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = 'sweep-fixture';
    $endpoint->url = 'https://hooks.example.test/audit';
    $endpoint->secretCurrent = 'sweep-secret-' . bin2hex(random_bytes(8));
    $endpoint->enabled = true;
    $endpoint->eventClasses = null;

    PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint);

    return $endpoint;
}

/**
 * Inserts an audit-log row, bypassing the chain writer. Every audit row pairs
 * with a `craft_elements` row via `id`, so the element row is allocated first
 * to satisfy the foreign key.
 */
function makeWebhookSweepAuditRow(): int
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
            'event' => 'webhook_sweep_fixture',
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

// =============================================================================
// Enqueue proof — assert on the queue, not on the exit code
// =============================================================================

it('pushes a WebhookForwardJob onto the queue', function() {
    makeSweepEndpoint();

    $runner = newWebhookRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::OK);
    expect($this->queue->pushed)->toHaveCount(1)
        ->and($this->queue->pushed[0])->toBeInstanceOf(WebhookForwardJob::class);
    expect(implode('', $runner->stdoutBuffer))->toContain('enqueued');
});

// =============================================================================
// End to end — the enqueued job reaches the batcher and delivers rows
// =============================================================================

it('enqueues a job that delivers pending audit rows to the endpoint', function() {
    $endpoint = makeSweepEndpoint();
    $rowA = makeWebhookSweepAuditRow();
    makeWebhookSweepAuditRow();
    $rowC = makeWebhookSweepAuditRow();

    // One accepted delivery per audit row.
    for ($i = 0; $i < 3; $i++) {
        $this->mockHandler->append(new Response(200));
    }

    $exitCode = newWebhookRunner()->runAction('run');
    expect($exitCode)->toBe(ExitCode::OK);

    /** @var WebhookForwardJob $job */
    $job = $this->queue->pushed[0];

    // Drive the captured job the way a queue worker would, feeding each
    // spawned batch back in. One endpoint means one batch, but running it
    // through the campaign helper proves the job reaches its batcher rather
    // than only its `processItem`.
    $batches = CapturingQueue::runCampaign($job, batchSize: 1);

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

    expect($batches)->toBe(1)
        ->and((int)$reloaded->lastDeliveredRowId)->toBe($rowC);
});

// =============================================================================
// Edition gate — sub-Enterprise fails visibly
// =============================================================================

it('refuses to run the sweep on a sub-Enterprise edition and enqueues nothing', function() {
    makeSweepEndpoint();
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $runner = newWebhookRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $runner->stderrBuffer))->toContain('Enterprise edition');
    expect($this->queue->pushed)->toBeEmpty();
});

it('refuses to run the sweep on Lite and enqueues nothing', function() {
    makeSweepEndpoint();
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $runner = newWebhookRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $runner->stderrBuffer))->toContain('Enterprise edition');
    expect($this->queue->pushed)->toBeEmpty();
});

// =============================================================================
// Terminal help — Yii renders these docblocks verbatim
// =============================================================================

it('renders real help text rather than a class name', function() {
    // The REAL controller, not the capturing subclass: Yii reads line 2 of
    // whatever class it is handed, and the subclass carries its own docblock.
    $controller = new WebhookController('webhook', PasswordPolicy::$plugin);

    expect($controller->getHelpSummary())
        ->toBe('Manages webhook endpoints and enqueues the webhook delivery sweep.')
        ->and($controller->getHelp())->toContain('cron');

    /** @var \yii\base\Action<WebhookController> $action */
    $action = $controller->createAction('run');

    expect($controller->getActionHelpSummary($action))
        ->toContain('delivers pending audit rows');
});

// =============================================================================
// Nothing configured — no endpoint means no job
// =============================================================================

it('enqueues nothing when no endpoint is active', function() {
    $runner = newWebhookRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::OK);
    expect(implode('', $runner->stdoutBuffer))->toContain('No active webhook endpoints');
    expect($this->queue->pushed)->toBeEmpty();
});
