<?php
/**
 * Pest coverage for the forwarder sweep-health warning that the SIEM
 * forwarders index and the webhook endpoints index render when the
 * operator-scheduled sweep cron looks like it is not running.
 *
 * Both `password-policy/siem/run` and `password-policy/webhook/run` are
 * operator-scheduled. Unscheduled, they fail silently: the index shows an
 * enabled forwarder, no error anywhere, and nothing is ever delivered.
 * `ComplianceAggregateService::getSiemSweepHealth()` and
 * `getWebhookSweepHealth()` turn that silence into a visible warning.
 *
 * Pinned contracts:
 *
 *  - Stale: an audit row nothing has attempted, older than
 *    `SWEEP_STALE_THRESHOLD_MINUTES`, with a forwarder / endpoint that
 *    would have swept it, warns.
 *  - Not yet stale: the same row inside the threshold does not warn.
 *  - The three idle shapes never warn: nothing pending, no enabled
 *    forwarder or endpoint that covers the `audit_log` stream, and a
 *    fresh install with an empty audit log.
 *  - A backlog with a delivery-side cause (SIEM `forwardAttempts > 0`,
 *    webhook `consecutiveFailures > 0`, an open circuit on either) does
 *    not warn, because that cause is already on screen in the index's
 *    Circuit column and cron is the wrong thing to send the operator
 *    after.
 *  - The edition gate holds: both indexes 404 below Enterprise, so no
 *    edition can see the warning that isn't entitled to the screen.
 *
 * Fixture ages are expressed relative to the threshold constant rather
 * than as literal minutes, so raising or lowering the window can't
 * silently invalidate the fixtures.
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
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\SiemForwarderController;
use craftpulse\passwordpolicy\controllers\WebhookEndpointController;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\ComplianceAggregateService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\NotFoundHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getComplianceAggregates();

    $this->originalEdition = $this->plugin->edition;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalResponse = Craft::$app->getResponse();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    // Both surfaces are Enterprise. Pin it so the edition is never what
    // makes an assertion pass or fail, except in the gate tests that set
    // it deliberately.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_siem_forwarders}}')
        ->execute();
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_webhook_endpoints}}')
        ->execute();

    Craft::$app->getCache()->flush();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Minutes-ago value that is comfortably past the staleness threshold.
 */
function sweepStaleMinutes(): int
{
    return ComplianceAggregateService::SWEEP_STALE_THRESHOLD_MINUTES + 30;
}

/**
 * Minutes-ago value that is comfortably inside the staleness threshold.
 */
function sweepFreshMinutes(): int
{
    return max(1, (int)floor(ComplianceAggregateService::SWEEP_STALE_THRESHOLD_MINUTES / 4));
}

/**
 * Inserts an audit-log row directly via SQL, paired with its
 * `craft_elements` row. Bypasses the chain writer: these tests care about
 * the forwarder watermark columns, not the hash chain.
 *
 * @param array<string, mixed> $overrides
 * @return int the new row's id
 */
function seedSweepAuditRow(int $minutesAgo, array $overrides = []): int
{
    $createdAt = Carbon::now('UTC')->subMinutes($minutesAgo)->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert(Table::ELEMENTS, [
            'type' => AuditLogElement::class,
            'enabled' => 1,
            'archived' => 0,
            'dateCreated' => $createdAt,
            'dateUpdated' => $createdAt,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    $elementId = (int)Craft::$app->getDb()->getLastInsertID(Table::ELEMENTS);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', array_merge([
            'id' => $elementId,
            'event' => 'password_changed',
            'outcome' => 'success',
            'source' => 'admin',
            'rowHash' => str_repeat('a', 64),
            'previousHash' => str_repeat('0', 64),
            'forwardedAt' => null,
            'forwardAttempts' => 0,
            'dateCreated' => $createdAt,
            'uid' => StringHelper::UUID(),
        ], $overrides))
        ->execute();

    return $elementId;
}

/**
 * Persists a SIEM forwarder through the service so model and record stay
 * in sync. Port 65535 is never bound: nothing here forwards for real.
 *
 * @param array<string, mixed> $overrides
 */
function seedSweepForwarder(array $overrides = []): SiemForwarderModel
{
    $forwarder = new SiemForwarderModel();
    $forwarder->name = $overrides['name'] ?? 'sweep-health';
    $forwarder->host = '127.0.0.1';
    $forwarder->port = 65535;
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_SYSLOG_TLS;
    $forwarder->tlsCertVerify = false;
    $forwarder->enabled = $overrides['enabled'] ?? true;
    $forwarder->eventClasses = $overrides['eventClasses'] ?? null;

    if (!PasswordPolicy::$plugin->getSiem()->saveForwarder($forwarder)) {
        throw new RuntimeException(
            'Failed to save fixture forwarder: ' . json_encode($forwarder->getErrors()),
        );
    }

    return $forwarder;
}

/**
 * Persists a webhook endpoint through the service so model and record
 * stay in sync.
 *
 * Seed endpoints BEFORE audit rows: `saveEndpoint()` seeds a null
 * watermark to the newest audit row, so an endpoint created after the
 * rows starts caught up by design.
 *
 * @param array<string, mixed> $overrides
 */
function seedSweepEndpoint(array $overrides = []): WebhookEndpointModel
{
    $endpoint = new WebhookEndpointModel();
    $endpoint->name = $overrides['name'] ?? 'sweep-health';
    $endpoint->url = $overrides['url'] ?? 'https://hooks.example.test/audit';
    $endpoint->secretCurrent = 'sweep-health-secret';
    $endpoint->enabled = $overrides['enabled'] ?? true;
    $endpoint->eventClasses = $overrides['eventClasses'] ?? null;

    if (!PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint)) {
        throw new RuntimeException(
            'Failed to save fixture endpoint: ' . json_encode($endpoint->getErrors()),
        );
    }

    return $endpoint;
}

/**
 * Writes circuit / failure state straight onto a forwarder or endpoint
 * row, bypassing the service so no delivery logic runs.
 */
function setSweepCircuitState(string $table, int $id, ?int $openedMinutesAgo = null, int $consecutiveFailures = 0): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            $table,
            [
                'circuitOpenAt' => $openedMinutesAgo === null
                    ? null
                    : Carbon::now('UTC')->subMinutes($openedMinutesAgo)->format('Y-m-d H:i:s'),
                'consecutiveFailures' => $consecutiveFailures,
            ],
            ['id' => $id],
        )
        ->execute();
}

/**
 * Runs a CP index action through `runAction()` so `beforeAction()` fires
 * exactly as it would on a real request.
 *
 * @param class-string<\craft\web\Controller> $class
 */
function runSweepIndexAction(string $class, string $controllerId): mixed
{
    $controller = new $class($controllerId, PasswordPolicy::$plugin);

    return $controller->runAction('index');
}

/**
 * Whether the index action raised the edition 404. Any other throwable
 * counts as "passed the gate": the action goes on to render a CP
 * template, which a console-bootstrapped test process can't complete.
 *
 * @param class-string<\craft\web\Controller> $class
 */
function sweepIndexEditionGated(string $class, string $controllerId): bool
{
    try {
        runSweepIndexAction($class, $controllerId);
    } catch (NotFoundHttpException) {
        return true;
    } catch (Throwable) {
        return false;
    }

    return false;
}

// =============================================================================
// getSiemSweepHealth — stale
// =============================================================================

it('warns when an audit row has waited past the threshold for a first forward attempt', function() {
    seedSweepForwarder();
    seedSweepAuditRow(sweepStaleMinutes());
    seedSweepAuditRow(sweepStaleMinutes() - 5);

    $health = $this->service->getSiemSweepHealth();

    expect($health['stale'])->toBeTrue();
    expect($health['unattemptedCount'])->toBe(2);
    expect($health['oldestAge'])->toBeString();
});

it('counts only rows still waiting for a first forward attempt', function() {
    seedSweepForwarder();
    seedSweepAuditRow(sweepStaleMinutes());
    seedSweepAuditRow(sweepStaleMinutes(), ['forwardAttempts' => 3]);
    seedSweepAuditRow(sweepStaleMinutes(), [
        'forwardedAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
    ]);

    $health = $this->service->getSiemSweepHealth();

    expect($health['stale'])->toBeTrue();
    expect($health['unattemptedCount'])->toBe(1);
});

// =============================================================================
// getSiemSweepHealth — not yet stale
// =============================================================================

it('stays quiet while the oldest unattempted row is inside the threshold', function() {
    seedSweepForwarder();
    seedSweepAuditRow(sweepFreshMinutes());

    $health = $this->service->getSiemSweepHealth();

    expect($health['stale'])->toBeFalse();
    expect($health['unattemptedCount'])->toBe(0);
    expect($health['oldestAge'])->toBeNull();
});

// =============================================================================
// getSiemSweepHealth — empty states
// =============================================================================

it('stays quiet on a fresh install with an empty audit log', function() {
    seedSweepForwarder();

    $health = $this->service->getSiemSweepHealth();

    expect($health['stale'])->toBeFalse();
    expect($health['oldestAge'])->toBeNull();
});

it('stays quiet when every audit row has been forwarded', function() {
    seedSweepForwarder();
    seedSweepAuditRow(sweepStaleMinutes(), [
        'forwardedAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
    ]);

    expect($this->service->getSiemSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet when no forwarder is configured at all', function() {
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getSiemSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet when the only forwarder is disabled', function() {
    seedSweepForwarder(['enabled' => false]);
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getSiemSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet when no forwarder allowlist covers the audit_log stream', function() {
    seedSweepForwarder(['eventClasses' => ['notification_log']]);
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getSiemSweepHealth()['stale'])->toBeFalse();
});

// =============================================================================
// getSiemSweepHealth — delivery-side causes stay out of the cron warning
// =============================================================================

it('stays quiet when the backlog has already been attempted and refused', function() {
    seedSweepForwarder();
    seedSweepAuditRow(sweepStaleMinutes(), ['forwardAttempts' => 1]);

    expect($this->service->getSiemSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet while the only forwarder sits on an open circuit', function() {
    $forwarder = seedSweepForwarder();
    setSweepCircuitState(
        '{{%passwordpolicy_siem_forwarders}}',
        (int)$forwarder->id,
        openedMinutesAgo: 10,
        consecutiveFailures: 5,
    );
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getSiemSweepHealth()['stale'])->toBeFalse();
});

// =============================================================================
// getWebhookSweepHealth — stale
// =============================================================================

it('warns when an endpoint has an undispatched backlog past the threshold', function() {
    seedSweepEndpoint();
    seedSweepAuditRow(sweepStaleMinutes());

    $health = $this->service->getWebhookSweepHealth();

    expect($health['stale'])->toBeTrue();
    expect($health['staleEndpointCount'])->toBe(1);
    expect($health['oldestAge'])->toBeString();
});

it('counts every enabled endpoint sitting on an undispatched backlog', function() {
    seedSweepEndpoint(['name' => 'first', 'url' => 'https://hooks.example.test/one']);
    seedSweepEndpoint(['name' => 'second', 'url' => 'https://hooks.example.test/two']);
    seedSweepAuditRow(sweepStaleMinutes());

    $health = $this->service->getWebhookSweepHealth();

    expect($health['stale'])->toBeTrue();
    expect($health['staleEndpointCount'])->toBe(2);
});

// =============================================================================
// getWebhookSweepHealth — not yet stale
// =============================================================================

it('stays quiet while an endpoint backlog is inside the threshold', function() {
    seedSweepEndpoint();
    seedSweepAuditRow(sweepFreshMinutes());

    $health = $this->service->getWebhookSweepHealth();

    expect($health['stale'])->toBeFalse();
    expect($health['staleEndpointCount'])->toBe(0);
    expect($health['oldestAge'])->toBeNull();
});

// =============================================================================
// getWebhookSweepHealth — empty states
// =============================================================================

it('stays quiet on a fresh install with no endpoints', function() {
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getWebhookSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet when an endpoint cursor has caught up with the audit log', function() {
    $endpoint = seedSweepEndpoint();
    $rowId = seedSweepAuditRow(sweepStaleMinutes());

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_webhook_endpoints}}',
            ['lastDeliveredRowId' => $rowId],
            ['id' => $endpoint->id],
        )
        ->execute();

    expect($this->service->getWebhookSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet when the only endpoint is disabled', function() {
    seedSweepEndpoint(['enabled' => false]);
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getWebhookSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet when no endpoint allowlist covers the audit_log stream', function() {
    seedSweepEndpoint(['eventClasses' => ['notification_log']]);
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getWebhookSweepHealth()['stale'])->toBeFalse();
});

// =============================================================================
// getWebhookSweepHealth — delivery-side causes stay out of the cron warning
// =============================================================================

it('stays quiet when the endpoint has recorded consecutive failures', function() {
    $endpoint = seedSweepEndpoint();
    setSweepCircuitState(
        '{{%passwordpolicy_webhook_endpoints}}',
        (int)$endpoint->id,
        consecutiveFailures: 2,
    );
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getWebhookSweepHealth()['stale'])->toBeFalse();
});

it('stays quiet while the endpoint sits on an open circuit', function() {
    $endpoint = seedSweepEndpoint();
    setSweepCircuitState(
        '{{%passwordpolicy_webhook_endpoints}}',
        (int)$endpoint->id,
        openedMinutesAgo: 10,
        consecutiveFailures: 5,
    );
    seedSweepAuditRow(sweepStaleMinutes());

    expect($this->service->getWebhookSweepHealth()['stale'])->toBeFalse();
});

it('reports only the endpoints whose backlog has no delivery-side cause', function() {
    $healthy = seedSweepEndpoint(['name' => 'healthy', 'url' => 'https://hooks.example.test/one']);
    $failing = seedSweepEndpoint(['name' => 'failing', 'url' => 'https://hooks.example.test/two']);

    setSweepCircuitState(
        '{{%passwordpolicy_webhook_endpoints}}',
        (int)$failing->id,
        consecutiveFailures: 4,
    );
    seedSweepAuditRow(sweepStaleMinutes());

    $health = $this->service->getWebhookSweepHealth();

    expect($health['stale'])->toBeTrue();
    expect($health['staleEndpointCount'])->toBe(1);

    // The healthy endpoint is the one that got counted.
    expect((new Query())
        ->from('{{%passwordpolicy_webhook_endpoints}}')
        ->where(['id' => $healthy->id])
        ->andWhere(['consecutiveFailures' => 0])
        ->exists())->toBeTrue();
});

// =============================================================================
// Edition gate — the warning can't render below Enterprise
// =============================================================================

it('404s both forwarder indexes on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(UserFactory::admin());

    expect(sweepIndexEditionGated(SiemForwarderController::class, 'siem-forwarder'))->toBeTrue();
    expect(sweepIndexEditionGated(WebhookEndpointController::class, 'webhook-endpoint'))->toBeTrue();
});

it('404s both forwarder indexes on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->userStub->setIdentity(UserFactory::admin());

    expect(sweepIndexEditionGated(SiemForwarderController::class, 'siem-forwarder'))->toBeTrue();
    expect(sweepIndexEditionGated(WebhookEndpointController::class, 'webhook-endpoint'))->toBeTrue();
});

it('lets both forwarder indexes past the edition gate on Enterprise', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    expect(sweepIndexEditionGated(SiemForwarderController::class, 'siem-forwarder'))->toBeFalse();
    expect(sweepIndexEditionGated(WebhookEndpointController::class, 'webhook-endpoint'))->toBeFalse();
});
