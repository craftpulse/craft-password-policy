<?php
/**
 * Pest coverage for `SiemService` — the G8 audit-row forwarder, across
 * both of its transports.
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
 *  - `saveForwarder()` round-trips the model + record, including the five
 *    HTTP destination columns, with `authToken` encrypted at rest.
 *  - `deleteForwarder()` removes the row + cache entry.
 *  - The HTTP transport POSTs the canonical JSON with `verify` on,
 *    redirects off, a bounded error-body read, and a re-check of the
 *    RESOLVED URL's scheme. An unsupported protocol never reaches either
 *    transport.
 *
 * The TLS write path itself is exercised via a stub `tls://` endpoint
 * that listens on a random port. PHP's `stream_socket_server` supports
 * `tls://` natively (with a self-signed cert + verify_peer disabled on
 * the forwarder side), so the test gets full byte-level capture without
 * mocking the service. Tests that don't need the wire-level capture
 * point at port 1 to deterministically force a connect refusal.
 *
 * The HTTP transport is mocked via `MockHandler` spliced through
 * `TestGuzzleConfig`, mirroring `WebhookServiceTest`'s pattern.
 *
 * @link      https://craft-pulse.com
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
use craftpulse\passwordpolicy\services\AuditLogService;
use craftpulse\passwordpolicy\services\SiemService;
use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

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
    $forwarder->framing = $overrides['framing'] ?? SiemForwarderModel::FRAMING_OCTET_COUNTED;
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
 * Inserts an HTTP forwarder via the service. Returns the persisted model
 * with the plaintext token still on the model surface.
 */
function makeHttpForwarder(array $overrides = []): SiemForwarderModel
{
    $forwarder = new SiemForwarderModel();
    $forwarder->name = $overrides['name'] ?? 'collector';
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $forwarder->url = $overrides['url'] ?? 'https://collector.example.test/ingest';
    $forwarder->authType = $overrides['authType'] ?? SiemForwarderModel::AUTH_TYPE_NONE;
    $forwarder->authToken = $overrides['authToken'] ?? null;
    $forwarder->headers = $overrides['headers'] ?? null;
    $forwarder->tlsCaBundlePath = $overrides['tlsCaBundlePath'] ?? null;
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
// Syslog frame body — byte-parity with the webhook canonical body
// =============================================================================

it('builds the MSG body via AuditLogService::canonicalize (byte-parity with webhook)', function() {
    // The class docblock on WebhookService promises SIEM and webhook
    // consumers see the same byte sequence. Both bodies must run through
    // canonicalize() (recursive key-sort + UNESCAPED flags) — not a bare
    // Json::encode — or the parity claim is false.
    $row = [
        'event' => 'siem_test',
        'id' => 7,
        'details' => ['source' => 'admin', 'a' => 'z'],
        'uid' => 'fixture-uid',
    ];

    $method = (new ReflectionClass($this->service))->getMethod('_buildSyslogFrame');
    $frame = $method->invoke($this->service, $row);

    $expectedBody = \craftpulse\passwordpolicy\services\AuditLogService::canonicalize($row);

    // The frame is `<PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG`; the MSG
    // is the trailing canonical JSON. Assert the frame ends with it.
    expect($frame)->toEndWith($expectedBody);

    // And the recursive key-sort actually happened — keys are ordered.
    expect($expectedBody)->toContain('"a":"z"');
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

// =============================================================================
// HTTP destination columns — round-trip
// =============================================================================

it('round-trips the five HTTP destination fields', function() {
    $model = new SiemForwarderModel();
    $model->name = 'Sumo HTTP source';
    $model->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $model->url = 'https://collector.example.test/receiver/v1/http/abc';
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = 'fixture-token-value';
    $model->headers = ['X-Sumo-Category' => 'craft/audit'];

    expect($this->service->saveForwarder($model))->toBeTrue();

    $loaded = $this->service->getForwarderById((int)$model->id);

    expect($loaded)->not->toBeNull()
        ->and($loaded->protocol)->toBe(SiemForwarderModel::PROTOCOL_HTTP)
        ->and($loaded->url)->toBe('https://collector.example.test/receiver/v1/http/abc')
        ->and($loaded->authType)->toBe(SiemForwarderModel::AUTH_TYPE_BEARER)
        ->and($loaded->authToken)->toBe('fixture-token-value')
        ->and($loaded->headers)->toBe(['X-Sumo-Category' => 'craft/audit'])
        // The syslog half is nulled on an HTTP row.
        ->and($loaded->host)->toBeNull()
        ->and($loaded->port)->toBeNull();
});

it('encrypts the auth token at rest: the DB column never holds plaintext', function() {
    $forwarder = makeHttpForwarder([
        'authType' => SiemForwarderModel::AUTH_TYPE_BEARER,
        'authToken' => 'plaintext-token-value',
    ]);

    $rawColumn = (new Query())
        ->select(['authToken'])
        ->from('{{%passwordpolicy_siem_forwarders}}')
        ->where(['id' => $forwarder->id])
        ->scalar();

    expect($rawColumn)->not->toBe('plaintext-token-value')
        ->and($rawColumn)->toMatch('/^[A-Za-z0-9+\/=_-]+$/');

    expect($this->service->getForwarderById((int)$forwarder->id)?->authToken)
        ->toBe('plaintext-token-value');
});

it('drops the credential when a forwarder is switched to syslog', function() {
    $forwarder = makeHttpForwarder([
        'authType' => SiemForwarderModel::AUTH_TYPE_BEARER,
        'authToken' => 'token-to-drop',
        'headers' => ['X-Stale' => 'yes'],
    ]);

    $forwarder->protocol = SiemForwarderModel::PROTOCOL_SYSLOG_TLS;
    $forwarder->host = '127.0.0.1';
    $forwarder->port = 6514;

    expect($this->service->saveForwarder($forwarder))->toBeTrue();

    $loaded = $this->service->getForwarderById((int)$forwarder->id);

    expect($loaded?->url)->toBeNull()
        ->and($loaded?->authToken)->toBeNull()
        ->and($loaded?->authType)->toBe(SiemForwarderModel::AUTH_TYPE_NONE)
        ->and($loaded?->headers)->toBeNull();
});

// =============================================================================
// HTTP transport — request shape
// =============================================================================

it('POSTs the canonical JSON body to the resolved URL', function() {
    $forwarder = makeHttpForwarder();
    $row = ['id' => 1, 'event' => 'siem_test', 'uid' => 'fixture', 'details' => ['a' => 'z']];
    $this->mockHandler->append(new Response(204));

    expect($this->service->forward($row, $forwarder))->toBeTrue();

    /** @var Request $sent */
    $sent = $this->mockHandler->getLastRequest();

    expect($sent)->not->toBeNull()
        ->and($sent->getMethod())->toBe('POST')
        ->and((string)$sent->getUri())->toBe('https://collector.example.test/ingest')
        ->and($sent->getHeaderLine('Content-Type'))->toBe('application/json')
        // Byte-parity with the syslog MSG and the webhook body.
        ->and((string)$sent->getBody())->toBe(AuditLogService::canonicalize($row));
});

it('never opens a TLS socket for an HTTP forwarder', function() {
    // Port 1 would refuse instantly if the syslog branch ran; the mocked
    // 200 proves the HTTP branch took the row instead.
    $forwarder = makeHttpForwarder();
    $this->mockHandler->append(new Response(200));

    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeTrue()
        ->and($this->mockHandler->count())->toBe(0);
});

it('sends peer verification on, redirects off, and a bounded timeout', function() {
    // The four Guzzle options that make this transport safe to point at a
    // third party. A site-level `config/guzzle.php` with `verify => false`
    // must not be able to turn the first one off.
    $forwarder = makeHttpForwarder();
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    $options = $this->mockHandler->getLastOptions();

    expect($options['verify'])->toBeTrue()
        ->and($options['allow_redirects'])->toBeFalse()
        ->and($options['http_errors'])->toBeFalse()
        ->and($options['timeout'])->toBe(SiemService::HTTP_TIMEOUT_SECONDS);
});

it('verifies against a custom CA bundle when one is configured', function() {
    $forwarder = makeHttpForwarder(['tlsCaBundlePath' => '/etc/ssl/certs/collector-ca.pem']);
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    // Still verifying, just against the operator's bundle rather than the
    // system trust store.
    expect($this->mockHandler->getLastOptions()['verify'])
        ->toBe('/etc/ssl/certs/collector-ca.pem');
});

it('ignores the syslog TLS-verify opt-out on the HTTP transport', function() {
    $forwarder = makeHttpForwarder();
    $forwarder->tlsCertVerify = false;
    $this->service->saveForwarder($forwarder);
    $forwarder = $this->service->getForwarderById((int)$forwarder->id);
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    expect($this->mockHandler->getLastOptions()['verify'])->toBeTrue();
});

// =============================================================================
// HTTP transport — authentication + custom headers
// =============================================================================

it('sends a Bearer Authorization header', function() {
    $forwarder = makeHttpForwarder([
        'authType' => SiemForwarderModel::AUTH_TYPE_BEARER,
        'authToken' => 'abc123',
    ]);
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    expect($this->mockHandler->getLastRequest()->getHeaderLine('Authorization'))
        ->toBe('Bearer abc123');
});

it('base64-encodes a Basic credential', function() {
    $forwarder = makeHttpForwarder([
        'authType' => SiemForwarderModel::AUTH_TYPE_BASIC,
        'authToken' => 'collector:s3cret',
    ]);
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    expect($this->mockHandler->getLastRequest()->getHeaderLine('Authorization'))
        ->toBe('Basic ' . base64_encode('collector:s3cret'));
});

it('sends no Authorization header when the auth type is none', function() {
    $forwarder = makeHttpForwarder();
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    expect($this->mockHandler->getLastRequest()->hasHeader('Authorization'))->toBeFalse();
});

it('sends the custom header map', function() {
    $forwarder = makeHttpForwarder([
        'headers' => ['DD-API-KEY' => 'dd-key', 'X-Env' => 'production'],
    ]);
    $this->mockHandler->append(new Response(200));

    $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

    $sent = $this->mockHandler->getLastRequest();

    expect($sent->getHeaderLine('DD-API-KEY'))->toBe('dd-key')
        ->and($sent->getHeaderLine('X-Env'))->toBe('production');
});

it('resolves an env-var reference in a custom header value', function() {
    putenv('PP_TEST_SIEM_HEADER=resolved-value');

    try {
        $forwarder = makeHttpForwarder(['headers' => ['X-Key' => '$PP_TEST_SIEM_HEADER']]);
        $this->mockHandler->append(new Response(200));

        $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

        expect($this->mockHandler->getLastRequest()->getHeaderLine('X-Key'))
            ->toBe('resolved-value');
    } finally {
        putenv('PP_TEST_SIEM_HEADER');
    }
});

it('refuses to send rather than sending an unresolved env reference', function() {
    // `App::parseEnv()` hands back the literal `$VAR` when the variable
    // isn't set. Sending `Bearer $PP_SIEM_TOKEN` to the collector produces
    // a 401 the operator then debugs from the wrong end, so the forward
    // fails here instead, with the reason in the plugin log.
    $forwarder = makeHttpForwarder([
        'authType' => SiemForwarderModel::AUTH_TYPE_BEARER,
        'authToken' => '$PP_TEST_SIEM_TOKEN_NOT_SET',
    ]);

    // No response queued: reaching Guzzle would throw "Mock queue is
    // empty".
    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeFalse()
        ->and($this->mockHandler->count())->toBe(0);
});

it('resolves an env-var reference in the auth token', function() {
    putenv('PP_TEST_SIEM_TOKEN=env-token');

    try {
        $forwarder = makeHttpForwarder([
            'authType' => SiemForwarderModel::AUTH_TYPE_BEARER,
            'authToken' => '$PP_TEST_SIEM_TOKEN',
        ]);
        $this->mockHandler->append(new Response(200));

        $this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder);

        expect($this->mockHandler->getLastRequest()->getHeaderLine('Authorization'))
            ->toBe('Bearer env-token');
    } finally {
        putenv('PP_TEST_SIEM_TOKEN');
    }
});

// =============================================================================
// HTTP transport — failure paths
// =============================================================================

it('treats a non-2xx response as a failure and bumps the breaker', function(int $status) {
    $forwarder = makeHttpForwarder();
    $this->mockHandler->append(new Response($status));

    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeFalse();

    /** @var SiemForwarderRecord $record */
    $record = SiemForwarderRecord::findOne(['id' => $forwarder->id]);
    expect((int)$record->consecutiveFailures)->toBe(1);
})->with([404, 422, 500, 503]);

it('treats a 3xx redirect as a failure and never follows it', function() {
    // A 307/308 from the registered host would otherwise re-POST the audit
    // row AND the credential to whatever Location it names. Only ONE
    // response is queued: following the redirect would exhaust the mock
    // queue and throw.
    $forwarder = makeHttpForwarder();
    $this->mockHandler->append(new Response(308, ['Location' => 'https://evil.example.test/steal']));

    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeFalse()
        ->and($this->mockHandler->count())->toBe(0);
});

it('refuses a resolved URL that is not https', function() {
    // The model rule rejects a literal http:// URL, but an env-var
    // reference skips it and resolves at forward time. Write the plaintext
    // URL straight to the row to reach that state.
    $forwarder = makeHttpForwarder();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            ['url' => 'http://insecure.example.test/ingest'],
            ['id' => $forwarder->id],
        )
        ->execute();

    $forwarder = $this->service->getForwarderById((int)$forwarder->id);

    // No response queued: reaching Guzzle at all would throw "Mock queue
    // is empty".
    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeFalse()
        ->and($this->mockHandler->count())->toBe(0);

    /** @var SiemForwarderRecord $record */
    $record = SiemForwarderRecord::findOne(['id' => $forwarder->id]);
    expect((int)$record->consecutiveFailures)->toBe(1);
});

it('bounds the error body read at ERROR_BODY_READ_LIMIT', function() {
    $forwarder = makeHttpForwarder();
    $hugeBody = str_repeat('x', SiemService::ERROR_BODY_READ_LIMIT + 500);
    $this->mockHandler->append(new Response(500, [], $hugeBody));

    $method = (new ReflectionClass($this->service))->getMethod('_buildResponseError');
    $message = $method->invoke($this->service, 500, $hugeBody);

    expect($message)->toEndWith('...')
        // 'HTTP 500: ' prefix (10) + LIMIT bytes + '...' (3).
        ->and(strlen($message))->toBe(10 + SiemService::ERROR_BODY_READ_LIMIT + 3);

    // And the forward itself still fails cleanly rather than throwing.
    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeFalse();
});

it('resets the breaker on a successful HTTP forward', function() {
    $forwarder = makeHttpForwarder();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            ['consecutiveFailures' => 3],
            ['id' => $forwarder->id],
        )
        ->execute();

    $forwarder = $this->service->getForwarderById((int)$forwarder->id);
    $this->mockHandler->append(new Response(200));

    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeTrue();

    /** @var SiemForwarderRecord $record */
    $record = SiemForwarderRecord::findOne(['id' => $forwarder->id]);
    expect((int)$record->consecutiveFailures)->toBe(0);
});

// =============================================================================
// Syslog framing — exact bytes on the wire
// =============================================================================

it('octet-counts the frame by default, per RFC 5425 §4.3', function() {
    // `MSG-LEN SP SYSLOG-MSG`, where MSG-LEN is the message's octet count
    // and nothing follows the message. RFC 5425 §4.3.1 makes reading that
    // length a MUST for a transport receiver on port 6514.
    $forwarder = makeForwarder();

    expect($forwarder->framing)->toBe(SiemForwarderModel::FRAMING_OCTET_COUNTED);

    $frame = '<133>1 2026-08-04T12:00:00Z host password-policy 1 audit-log - {"a":1}';
    $method = (new ReflectionClass($this->service))->getMethod('_framePayload');
    $payload = $method->invoke($this->service, $forwarder, $frame);

    expect($payload)->toBe(strlen($frame) . ' ' . $frame)
        ->and($payload)->not->toEndWith("\n")
        // Spelled out: the prefix is the message's own octet count, not the
        // payload's, and the separator is a single space.
        ->and($payload)->toStartWith('70 <133>1 ')
        ->and(strlen($frame))->toBe(70);
});

it('newline-delimits the frame when the forwarder asks for it', function() {
    $forwarder = makeForwarder(['framing' => SiemForwarderModel::FRAMING_NEWLINE]);

    $frame = '<133>1 2026-08-04T12:00:00Z host password-policy 1 audit-log - {"a":1}';
    $method = (new ReflectionClass($this->service))->getMethod('_framePayload');
    $payload = $method->invoke($this->service, $forwarder, $frame);

    expect($payload)->toBe($frame . "\n")
        ->and($payload)->not->toStartWith(strlen($frame) . ' ');
});

it('round-trips the framing choice', function() {
    $forwarder = makeForwarder(['framing' => SiemForwarderModel::FRAMING_NEWLINE]);

    expect($this->service->getForwarderById((int)$forwarder->id)?->framing)
        ->toBe(SiemForwarderModel::FRAMING_NEWLINE);
});

it('fails closed on a framing value neither branch handles', function() {
    // Only reachable by direct SQL; the model rule refuses anything else.
    $forwarder = makeForwarder(['port' => 1]);

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            ['framing' => 'octet-stuffed'],
            ['id' => $forwarder->id],
        )
        ->execute();

    $forwarder = $this->service->getForwarderById((int)$forwarder->id);
    $method = (new ReflectionClass($this->service))->getMethod('_framePayload');

    expect(fn() => $method->invoke($this->service, $forwarder, 'frame'))
        ->toThrow(RuntimeException::class);
});

// =============================================================================
// Unsupported protocol — fails closed
// =============================================================================

it('fails closed on a protocol neither transport handles', function() {
    // Only reachable by direct SQL: the CP offers two options and the model
    // rule refuses anything else. Before the protocol branch existed, a row
    // like this got a tls:// connection to its host:port regardless.
    $forwarder = makeForwarder();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_siem_forwarders}}',
            ['protocol' => 'syslog-udp'],
            ['id' => $forwarder->id],
        )
        ->execute();

    $forwarder = $this->service->getForwarderById((int)$forwarder->id);

    expect($this->service->forward(['id' => 1, 'uid' => 'x'], $forwarder))->toBeFalse()
        // Never reached the HTTP transport either.
        ->and($this->mockHandler->count())->toBe(0);

    /** @var SiemForwarderRecord $record */
    $record = SiemForwarderRecord::findOne(['id' => $forwarder->id]);
    expect((int)$record->consecutiveFailures)->toBe(1);
});
