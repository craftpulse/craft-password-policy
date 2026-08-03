<?php
/**
 * Pest coverage for `SiemController::actionRun` — the console trigger that
 * enqueues the Enterprise SIEM forward sweep.
 *
 * This file exists because the sweep had no trigger at all. `SiemForwardJob`
 * shipped with a batcher, a watermark, and a campaign test, and nothing in
 * `src/` ever pushed it: on a real Enterprise install every audit row kept
 * `forwardedAt = NULL` forever. A test asserting only the command's exit code
 * would have passed against that same void, so the assertions here are against
 * a CAPTURED QUEUE and, in the last test, against the rows the captured job
 * actually forwards.
 *
 * `CapturingQueue` is installed as the app's `queue` component so
 * `craft\helpers\Queue::push()` lands in it, and it captures at
 * `pushMessage()` — below the serializer — so what comes back out survived a
 * real serialize/unserialize round trip.
 *
 * Pins:
 *
 *  - The command pushes a `SiemForwardJob`, not merely returns `ExitCode::OK`.
 *  - The pushed job, run as a campaign, forwards every pending audit row.
 *  - A sub-Enterprise install fails visibly (non-zero exit, stderr message)
 *    and pushes nothing.
 *  - With no active forwarder the command enqueues nothing rather than
 *    filling the queue table with no-op jobs on every cron tick.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\console\controllers\SiemController;
use craftpulse\passwordpolicy\jobs\SiemForwardJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\SiemService;
use craftpulse\passwordpolicy\tests\Support\AcceptingSiemService;
use craftpulse\passwordpolicy\tests\Support\CapturingQueue;
use craftpulse\passwordpolicy\tests\Support\CapturingSiemController;
use yii\console\ExitCode;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    // A forwarder that accepts, and that reports itself active without a
    // database row. The command's "is anything configured" check and the
    // job's per-row forwarding both read this component.
    $this->siem = new AcceptingSiemService();
    $this->plugin->set('siem', $this->siem);

    // `Queue::push()` resolves the app's `queue` component, so swapping it is
    // what makes the enqueue observable.
    $this->originalQueue = Craft::$app->getQueue();
    $this->queue = new CapturingQueue();
    Craft::$app->set('queue', $this->queue);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    // The "nothing configured" test drops back to the real service, which
    // reads this table.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_siem_forwarders}}')
        ->execute();
});

afterEach(function() {
    // Restore both components. The plugin module and the app both memoize, so
    // a stub left in place would leak into every later file in the process.
    Craft::$app->set('queue', $this->originalQueue);
    $this->plugin->set('siem', SiemService::class);
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

function newSiemRunner(): CapturingSiemController
{
    return new CapturingSiemController('siem', PasswordPolicy::$plugin);
}

/**
 * Inserts an unforwarded audit-log row, bypassing the chain writer. Every audit
 * row pairs with a `craft_elements` row via `id`, so the element row is
 * allocated first to satisfy the foreign key.
 */
function makeSweepAuditRow(): int
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
            'event' => 'siem_sweep_fixture',
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
 * Counts audit rows still awaiting forwarding.
 */
function pendingSweepRowCount(): int
{
    return (int)(new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['forwardedAt' => null])
        ->count();
}

// =============================================================================
// Enqueue proof — assert on the queue, not on the exit code
// =============================================================================

it('pushes a SiemForwardJob onto the queue', function() {
    $runner = newSiemRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::OK);
    expect($this->queue->pushed)->toHaveCount(1)
        ->and($this->queue->pushed[0])->toBeInstanceOf(SiemForwardJob::class);
    expect(implode('', $runner->stdoutBuffer))->toContain('enqueued');
});

// =============================================================================
// End to end — the enqueued job reaches the batcher and processes rows
// =============================================================================

it('enqueues a job that forwards every pending audit row', function() {
    $ids = [];

    for ($i = 0; $i < 7; $i++) {
        $ids[] = makeSweepAuditRow();
    }

    expect(pendingSweepRowCount())->toBe(7);

    $exitCode = newSiemRunner()->runAction('run');
    expect($exitCode)->toBe(ExitCode::OK);

    /** @var SiemForwardJob $job */
    $job = $this->queue->pushed[0];

    // Drive the captured job the way a queue worker would, feeding each
    // spawned batch back in. A small batch size makes the fixture span
    // several batches, which is the only shape in which a campaign that
    // strands its tail is visible.
    $batches = CapturingQueue::runCampaign($job, batchSize: 3);

    expect($batches)->toBe(3)
        ->and(pendingSweepRowCount())->toBe(0)
        ->and($this->siem->forwardedIds)->toBe($ids);
});

// =============================================================================
// Edition gate — sub-Enterprise fails visibly
// =============================================================================

it('refuses to run on a sub-Enterprise edition and enqueues nothing', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $runner = newSiemRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $runner->stderrBuffer))->toContain('Enterprise edition');
    expect($this->queue->pushed)->toBeEmpty();
});

it('refuses to run on Lite and enqueues nothing', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $runner = newSiemRunner();
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
    $controller = new SiemController('siem', PasswordPolicy::$plugin);

    expect($controller->getHelpSummary())
        ->toBe('Enqueues the SIEM forward sweep for pending audit-log rows.')
        ->and($controller->getHelp())->toContain('cron');

    /** @var \yii\base\Action<SiemController> $action */
    $action = $controller->createAction('run');

    expect($controller->getActionHelpSummary($action))
        ->toContain('forwards pending audit rows');
});

// =============================================================================
// Nothing configured — no forwarder means no job
// =============================================================================

it('enqueues nothing when no forwarder is active', function() {
    // Real service against an empty forwarder table.
    $this->plugin->set('siem', SiemService::class);

    $runner = newSiemRunner();
    $exitCode = $runner->runAction('run');

    expect($exitCode)->toBe(ExitCode::OK);
    expect(implode('', $runner->stdoutBuffer))->toContain('No active SIEM forwarders');
    expect($this->queue->pushed)->toBeEmpty();
});
