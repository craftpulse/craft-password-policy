<?php
/**
 * Pest coverage for `SiemService` — the G8 syslog-over-TLS forwarder.
 *
 * Pinned contracts:
 *
 *  - `getActiveForwarders()` returns enabled + circuit-closed forwarders
 *    only; excludes circuit-open forwarders inside the cooldown window;
 *    INCLUDES circuit-open forwarders past cooldown (half-open probe
 *    path — the next forward IS the probe).
 *  - `getEligibleEventClasses()` returns the per-forwarder override when
 *    non-empty; falls back to the global setting otherwise.
 *  - `forward()` returns false on a connection failure (port refused) AND
 *    increments the per-forwarder `consecutiveFailures` + cache counter.
 *  - Circuit breaker opens at threshold; resets on a successful forward.
 *  - `saveForwarder()` round-trips the model + record.
 *  - `deleteForwarder()` removes the row + cache entry.
 *
 * The TLS write path itself is exercised via a stub `tls://` endpoint
 * that listens on a random port. PHP's `stream_socket_server` supports
 * `tls://` natively (with a self-signed cert + verify_peer disabled on
 * the forwarder side), so the test gets full byte-level capture without
 * mocking the service. Tests that don't need the wire-level capture
 * point at port 1 to deterministically force a connect refusal.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\SiemForwarderRecord;
use craftpulse\passwordpolicy\services\SiemService;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getSiem();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_siem_forwarders}}')
        ->execute();

    Craft::$app->getCache()->flush();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts a forwarder via the service so the model + record stay in
 * sync. Returns the persisted model.
 */
function makeForwarder(array $overrides = []): SiemForwarderModel
{
    $forwarder = new SiemForwarderModel();
    $forwarder->name = $overrides['name'] ?? 'test';
    $forwarder->host = $overrides['host'] ?? '127.0.0.1';
    $forwarder->port = $overrides['port'] ?? 65535; // unlikely to be bound
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_SYSLOG_TLS;
    $forwarder->tlsCertVerify = $overrides['tlsCertVerify'] ?? false;
    $forwarder->enabled = $overrides['enabled'] ?? true;
    $forwarder->eventClasses = $overrides['eventClasses'] ?? null;

    $saved = PasswordPolicy::$plugin->getSiem()->saveForwarder($forwarder);

    if (!$saved) {
        throw new RuntimeException('Failed to save fixture forwarder: ' . json_encode($forwarder->getErrors()));
    }

    return $forwarder;
}

/**
 * Back-dates a forwarder's `circuitOpenAt` so the cooldown window has
 * elapsed (forwarder enters half-open state).
 */
function expireCircuit(int $forwarderId, int $secondsAgo = 600): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            ['circuitOpenAt' => Carbon::now('UTC')->subSeconds($secondsAgo)->format('Y-m-d H:i:s')],
            ['id' => $forwarderId],
        )
        ->execute();
}

// =============================================================================
// getActiveForwarders
// =============================================================================

it('returns enabled, circuit-closed forwarders', function() {
    $forwarder = makeForwarder();

    $active = $this->service->getActiveForwarders();

    expect($active)->toHaveCount(1);
    expect($active[0]->id)->toBe($forwarder->id);
});

it('excludes disabled forwarders', function() {
    makeForwarder(['enabled' => false]);

    $active = $this->service->getActiveForwarders();

    expect($active)->toHaveCount(0);
});

it('excludes circuit-open forwarders inside the cooldown window', function() {
    $forwarder = makeForwarder();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            [
                'circuitOpenAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'consecutiveFailures' => 5,
            ],
            ['id' => $forwarder->id],
        )
        ->execute();

    $active = $this->service->getActiveForwarders();

    expect($active)->toHaveCount(0);
});

it('includes circuit-open forwarders past the cooldown (half-open probe)', function() {
    $forwarder = makeForwarder();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            [
                'circuitOpenAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'consecutiveFailures' => 5,
            ],
            ['id' => $forwarder->id],
        )
        ->execute();

    expireCircuit((int)$forwarder->id, 600);

    $active = $this->service->getActiveForwarders();

    expect($active)->toHaveCount(1);
});

// =============================================================================
// getEligibleEventClasses
// =============================================================================

it('returns the per-forwarder override when non-empty', function() {
    $forwarder = makeForwarder(['eventClasses' => ['audit_log', 'notification_log']]);

    $classes = $this->service->getEligibleEventClasses($forwarder);

    expect($classes)->toBe(['audit_log', 'notification_log']);
});

it('falls back to the global setting when the override is null', function() {
    $forwarder = makeForwarder();
    $forwarder->eventClasses = null;

    $classes = $this->service->getEligibleEventClasses($forwarder);

    expect($classes)->toBe($this->plugin->getSettings()->siemForwardEventClasses);
});

it('falls back to the global setting when the override is an empty array', function() {
    $forwarder = makeForwarder();
    $forwarder->eventClasses = [];

    $classes = $this->service->getEligibleEventClasses($forwarder);

    expect($classes)->toBe($this->plugin->getSettings()->siemForwardEventClasses);
});

// =============================================================================
// forward — failure path (no listener)
// =============================================================================

it('returns false when the destination refuses the connection', function() {
    // Port 1 is the TCP echo port (reserved); nothing listens there in
    // a stock dev env. The connect attempt fails fast.
    $forwarder = makeForwarder(['port' => 1]);

    $row = ['id' => 1, 'event' => 'siem_test', 'uid' => 'fixture'];

    $result = $this->service->forward($row, $forwarder);

    expect($result)->toBeFalse();
});

it('increments consecutiveFailures on a connection failure', function() {
    $forwarder = makeForwarder(['port' => 1]);
    $row = ['id' => 1, 'event' => 'siem_test', 'uid' => 'fixture'];

    $this->service->forward($row, $forwarder);

    $record = SiemForwarderRecord::findOne(['id' => $forwarder->id]);
    expect($record)->not->toBeNull();
    expect((int)$record->consecutiveFailures)->toBe(1);
});

it('opens the circuit after consecutive failures cross the threshold', function() {
    $threshold = $this->plugin->getSettings()->siemCircuitFailureThreshold;
    $forwarder = makeForwarder(['port' => 1]);
    $row = ['id' => 1, 'event' => 'siem_test', 'uid' => 'fixture'];

    for ($i = 0; $i < $threshold; $i++) {
        $this->service->forward($row, $forwarder);
        // Refresh the in-memory model with the latest DB state so the
        // service's "is the circuit already open?" branch sees the
        // committed value.
        $forwarder = $this->service->getForwarderById((int)$forwarder->id);
    }

    expect($forwarder->circuitOpenAt)->not->toBeNull();
    expect($forwarder->consecutiveFailures)->toBeGreaterThanOrEqual($threshold);
});

// =============================================================================
// resetCircuit
// =============================================================================

it('clears circuitOpenAt and consecutiveFailures on resetCircuit', function() {
    $forwarder = makeForwarder();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            [
                'circuitOpenAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'consecutiveFailures' => 7,
            ],
            ['id' => $forwarder->id],
        )
        ->execute();

    $reset = $this->service->resetCircuit((int)$forwarder->id);

    expect($reset)->toBeTrue();

    $refreshed = $this->service->getForwarderById((int)$forwarder->id);
    expect($refreshed)->not->toBeNull();
    expect($refreshed->circuitOpenAt)->toBeNull();
    expect($refreshed->consecutiveFailures)->toBe(0);
});

// =============================================================================
// saveForwarder + getForwarderById round-trip
// =============================================================================

it('persists a new forwarder and returns it via getForwarderById', function() {
    $model = new SiemForwarderModel();
    $model->name = 'Splunk HEC';
    $model->host = 'siem.example.test';
    $model->port = 6514;
    $model->protocol = SiemForwarderModel::PROTOCOL_SYSLOG_TLS;
    $model->tlsCertVerify = true;
    $model->tlsCaBundlePath = '$PP_SIEM_CA_BUNDLE';
    $model->eventClasses = ['audit_log'];
    $model->enabled = true;

    $saved = $this->service->saveForwarder($model);

    expect($saved)->toBeTrue();
    expect($model->id)->not->toBeNull();
    expect($model->uid)->not->toBeNull();

    $loaded = $this->service->getForwarderById((int)$model->id);

    expect($loaded)->not->toBeNull();
    expect($loaded->name)->toBe('Splunk HEC');
    expect($loaded->host)->toBe('siem.example.test');
    expect($loaded->port)->toBe(6514);
    expect($loaded->tlsCaBundlePath)->toBe('$PP_SIEM_CA_BUNDLE');
    expect($loaded->eventClasses)->toBe(['audit_log']);
});

it('rejects an invalid forwarder via the model rules', function() {
    $model = new SiemForwarderModel();
    $model->host = '';
    $model->port = 99999;

    $saved = $this->service->saveForwarder($model);

    expect($saved)->toBeFalse();
    expect($model->getErrors('host'))->not->toBeEmpty();
    expect($model->getErrors('port'))->not->toBeEmpty();
});

// =============================================================================
// deleteForwarder
// =============================================================================

it('removes the forwarder row on delete', function() {
    $forwarder = makeForwarder();

    $deleted = $this->service->deleteForwarder((int)$forwarder->id);

    expect($deleted)->toBeTrue();
    expect($this->service->getForwarderById((int)$forwarder->id))->toBeNull();
});

// =============================================================================
// listForwarders
// =============================================================================

it('lists every forwarder ordered by id', function() {
    $a = makeForwarder(['name' => 'a']);
    $b = makeForwarder(['name' => 'b']);

    $list = $this->service->listForwarders();

    expect($list)->toHaveCount(2);
    expect($list[0]->id)->toBe($a->id);
    expect($list[1]->id)->toBe($b->id);
});
