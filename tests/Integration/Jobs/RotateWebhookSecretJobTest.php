<?php
/**
 * Pest coverage for `RotateWebhookSecretJob` — the G9 dual-secret grace
 * window reaper.
 *
 * Pinned contracts:
 *
 *  - `secretRotatedAt` is stored as a NAIVE UTC datetime string. The
 *    grace-window calculation MUST parse it as UTC — parsing it in the
 *    site/app timezone skews `elapsed` by the UTC offset and mis-times
 *    the reap (reaps early or late by the offset).
 *  - A rotation whose grace window has elapsed reaps `secretPrevious`.
 *  - A rotation still inside the grace window is a no-op.
 *  - A null `secretRotatedAt` (bookkeeping gap) treats the window as
 *    elapsed and reaps defensively.
 *  - Edition gate: skips on Pro without touching state.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craftpulse\passwordpolicy\jobs\RotateWebhookSecretJob;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;

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

    Craft::$app->getCache()->flush();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts an endpoint with a populated `secretPrevious` and a
 * `secretRotatedAt` pinned `$rotatedSecondsAgo` in the past (naive UTC
 * string, as the DB stores it).
 */
function makeRotatedEndpoint(int $rotatedSecondsAgo): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = 'rotate-fixture';
    $endpoint->url = 'https://hooks.example.test/audit';
    $endpoint->secretCurrent = 'current-secret';
    $endpoint->secretPrevious = 'previous-secret';
    $endpoint->enabled = true;

    PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint);

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            [
                'secretRotatedAt' => Carbon::now('UTC')
                    ->subSeconds($rotatedSecondsAgo)
                    ->format('Y-m-d H:i:s'),
            ],
            ['id' => $endpoint->id],
        )
        ->execute();

    return $endpoint;
}

/**
 * Invokes the job's private `_gracePeriodElapsed` against a record.
 */
function invokeGracePeriodElapsed(RotateWebhookSecretJob $job, WebhookEndpointRecord $record): bool
{
    $method = (new ReflectionClass($job))->getMethod('_gracePeriodElapsed');

    return (bool)$method->invoke($job, $record);
}

// =============================================================================
// Grace-window timing — parsed as UTC
// =============================================================================

it('reaps secretPrevious once the grace window has elapsed', function() {
    $graceSeconds = max(1, $this->plugin->getSettings()->webhookSecretGracePeriodHours) * 3600;
    $endpoint = makeRotatedEndpoint($graceSeconds + 120);

    $job = new RotateWebhookSecretJob();
    $job->endpointId = (int)$endpoint->id;
    $job->execute(Craft::$app->getQueue());

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->secretPrevious)->toBeNull();
});

it('is a no-op while still inside the grace window', function() {
    $graceSeconds = max(1, $this->plugin->getSettings()->webhookSecretGracePeriodHours) * 3600;
    // 5 minutes shy of the window — well clear of any UTC-offset skew.
    $endpoint = makeRotatedEndpoint($graceSeconds - 300);

    $job = new RotateWebhookSecretJob();
    $job->endpointId = (int)$endpoint->id;
    $job->execute(Craft::$app->getQueue());

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->secretPrevious)->not->toBeNull();
});

it('parses the naive secretRotatedAt as UTC, not the site timezone', function() {
    // Force a BEHIND-UTC app timezone so the regression is deterministically
    // catchable rather than false-greening in a UTC CI env. The pre-fix code
    // parsed the naive UTC string in the app tz; for a negative offset that
    // shifts the instant later and shrinks `elapsed` below the window,
    // flipping the verdict to false. Honolulu is a fixed UTC-10 (no DST), so a
    // rotation pinned just window+60s old reads as ~10h short under the bug.
    // Parsed correctly as UTC it is genuinely past the window → reaped.
    // makeRotatedEndpoint stamps secretRotatedAt via explicit Carbon::now('UTC'),
    // so the STORED value is correct regardless of app tz — only the job's
    // read-back parse (the code under test) is affected.
    $originalTz = Craft::$app->getTimeZone();
    Craft::$app->setTimeZone('Pacific/Honolulu');

    try {
        $graceSeconds = max(1, $this->plugin->getSettings()->webhookSecretGracePeriodHours) * 3600;
        $endpoint = makeRotatedEndpoint($graceSeconds + 60);

        /** @var WebhookEndpointRecord $record */
        $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

        $job = new RotateWebhookSecretJob();

        expect(invokeGracePeriodElapsed($job, $record))->toBeTrue();
    } finally {
        Craft::$app->setTimeZone($originalTz);
    }
});

it('treats a null secretRotatedAt as elapsed (defensive reap)', function() {
    $endpoint = makeRotatedEndpoint(0);

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            ['secretRotatedAt' => null],
            ['id' => $endpoint->id],
        )
        ->execute();

    /** @var WebhookEndpointRecord $record */
    $record = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);

    $job = new RotateWebhookSecretJob();

    expect(invokeGracePeriodElapsed($job, $record))->toBeTrue();
});

// =============================================================================
// Edition gate
// =============================================================================

it('skips on Pro without reaping', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $graceSeconds = max(1, $this->plugin->getSettings()->webhookSecretGracePeriodHours) * 3600;
    $endpoint = makeRotatedEndpoint($graceSeconds + 120);

    $job = new RotateWebhookSecretJob();
    $job->endpointId = (int)$endpoint->id;
    $job->execute(Craft::$app->getQueue());

    /** @var WebhookEndpointRecord $reloaded */
    $reloaded = WebhookEndpointRecord::findOne(['id' => $endpoint->id]);
    expect($reloaded->secretPrevious)->not->toBeNull();
});
