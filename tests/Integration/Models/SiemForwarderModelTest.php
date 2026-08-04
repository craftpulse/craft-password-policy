<?php
/**
 * Pest coverage for `SiemForwarderModel` — the shared validation surface
 * of the two SIEM destinations.
 *
 * Pinned contracts:
 *
 *  - `protocol` accepts `syslog-tls` and `http`, nothing else.
 *  - Validation follows the protocol: the syslog transport requires
 *    `host` + `port`, the HTTP transport requires an https `url`.
 *  - A literal `http://` URL is refused. An env-var reference skips URL
 *    validation, because the value only exists once resolved (the
 *    service re-checks the resolved scheme).
 *  - `authToken` is required when `authType` is not `none`, encrypted by
 *    `toRecordAttributes()`, and absent from `fields()`.
 *  - `toRecordAttributes()` nulls the unused half of the row, so
 *    switching an HTTP forwarder to syslog drops its credential.
 *  - The custom header map rejects invalid names, transport-owned names,
 *    an `Authorization` entry that would collide with `authType`, and
 *    empty values.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\SiemForwarderModel;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns an unsaved, valid syslog forwarder model.
 */
function syslogForwarderModel(): SiemForwarderModel
{
    $model = new SiemForwarderModel();
    $model->protocol = SiemForwarderModel::PROTOCOL_SYSLOG_TLS;
    $model->host = 'siem.example.test';
    $model->port = SiemForwarderModel::DEFAULT_SYSLOG_TLS_PORT;

    return $model;
}

/**
 * Returns an unsaved, valid HTTP forwarder model.
 */
function httpForwarderModel(): SiemForwarderModel
{
    $model = new SiemForwarderModel();
    $model->protocol = SiemForwarderModel::PROTOCOL_HTTP;
    $model->url = 'https://collector.example.test/ingest';

    return $model;
}

// =============================================================================
// protocol range
// =============================================================================

it('accepts both shipped protocols', function() {
    expect(syslogForwarderModel()->validate())->toBeTrue()
        ->and(httpForwarderModel()->validate())->toBeTrue();
});

it('rejects an unsupported protocol', function() {
    $model = syslogForwarderModel();
    $model->protocol = 'syslog-udp';

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('protocol'))->not->toBeEmpty();
});

// =============================================================================
// Conditional requirements per transport
// =============================================================================

it('requires host and port on the syslog transport', function() {
    $model = syslogForwarderModel();
    $model->host = null;
    $model->port = null;

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('host'))->not->toBeEmpty()
        ->and($model->getErrors('port'))->not->toBeEmpty()
        // The URL belongs to the other transport and stays optional.
        ->and($model->getErrors('url'))->toBeEmpty();
});

it('requires a URL on the HTTP transport', function() {
    $model = httpForwarderModel();
    $model->url = null;

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('url'))->not->toBeEmpty();
});

it('does not require host or port on the HTTP transport', function() {
    $model = httpForwarderModel();
    $model->host = null;
    $model->port = null;

    expect($model->validate())->toBeTrue();
});

// =============================================================================
// URL scheme hardening
// =============================================================================

it('refuses a plaintext http URL', function() {
    $model = httpForwarderModel();
    $model->url = 'http://collector.example.test/ingest';

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('url'))->not->toBeEmpty();
});

it('accepts an env-var reference as the URL', function() {
    // Resolution happens at forward time, where the service re-checks the
    // resolved scheme. Validating the literal `$VAR` string as a URL would
    // reject every env-configured forwarder.
    $model = httpForwarderModel();
    $model->url = '$PP_SIEM_URL';

    expect($model->validate())->toBeTrue();
});

// =============================================================================
// authType + authToken
// =============================================================================

it('requires a token for bearer and basic authentication', function(string $authType) {
    $model = httpForwarderModel();
    $model->authType = $authType;
    $model->authToken = null;

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('authToken'))->not->toBeEmpty();
})->with([
    SiemForwarderModel::AUTH_TYPE_BEARER,
    SiemForwarderModel::AUTH_TYPE_BASIC,
]);

it('needs no token when authentication is none', function() {
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_NONE;

    expect($model->validate())->toBeTrue();
});

it('rejects an unsupported auth type', function() {
    $model = httpForwarderModel();
    $model->authType = 'oauth2';
    $model->authToken = 'x';

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('authType'))->not->toBeEmpty();
});

it('reports no stored credential on a model that was never hydrated', function() {
    // `getHasStoredCredential()` answers for the ROW, not the property, so a
    // hand-built model with a plaintext on it still has nothing stored.
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = 'typed-but-not-saved';

    expect($model->getHasStoredCredential())->toBeFalse();
});

it('still requires a credential on a new HTTP forwarder', function() {
    // The `required` rule is relaxed only when the row already holds one.
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = null;

    expect($model->getHasStoredCredential())->toBeFalse()
        ->and($model->validate())->toBeFalse()
        ->and($model->getErrors('authToken'))->not->toBeEmpty();
});

it('omits the auth token from the serialization surface', function() {
    // `actionSave` returns `asModelSuccess($forwarder, …)`, which
    // serializes through `fields()`. A token in there would be echoed
    // back to the browser on every save.
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = 'super-secret-token';

    $serialized = $model->toArray();

    expect($serialized)->not->toHaveKey('authToken')
        ->and(json_encode($serialized))->not->toContain('super-secret-token');
});

// =============================================================================
// toRecordAttributes — encryption + per-protocol nulling
// =============================================================================

it('encrypts the auth token on the way to the record', function() {
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = 'plaintext-token-value';

    $attributes = $model->toRecordAttributes();

    expect($attributes['authToken'])->not->toBe('plaintext-token-value')
        ->and($attributes['authToken'])->toMatch('/^[A-Za-z0-9+\/=_-]+$/');
});

it('drops the token when authentication is none', function() {
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_NONE;
    $model->authToken = 'left-over-token';

    expect($model->toRecordAttributes()['authToken'])->toBeNull();
});

it('nulls the HTTP half of the row on a syslog forwarder', function() {
    // A forwarder switched from HTTP to syslog must not keep a live
    // credential for a destination it no longer talks to.
    $model = syslogForwarderModel();
    $model->url = 'https://collector.example.test/ingest';
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = 'stale-token';
    $model->headers = ['X-Stale' => 'yes'];

    $attributes = $model->toRecordAttributes();

    expect($attributes['url'])->toBeNull()
        ->and($attributes['authType'])->toBe(SiemForwarderModel::AUTH_TYPE_NONE)
        ->and($attributes['authToken'])->toBeNull()
        ->and($attributes['headers'])->toBeNull()
        ->and($attributes['host'])->toBe('siem.example.test');
});

it('nulls the syslog half of the row on an HTTP forwarder', function() {
    $model = httpForwarderModel();
    $model->host = 'siem.example.test';
    $model->port = 6514;

    $attributes = $model->toRecordAttributes();

    expect($attributes['host'])->toBeNull()
        ->and($attributes['port'])->toBeNull()
        ->and($attributes['url'])->toBe('https://collector.example.test/ingest');
});

it('never writes circuit-breaker state through the model boundary', function() {
    // The forward path owns those two columns with targeted writes. A CP
    // save carrying whatever the edit screen loaded would clobber a
    // failure the sweep recorded in between.
    $attributes = httpForwarderModel()->toRecordAttributes();

    expect($attributes)->not->toHaveKey('consecutiveFailures')
        ->and($attributes)->not->toHaveKey('circuitOpenAt');
});

// =============================================================================
// Custom header validation
// =============================================================================

it('accepts a well-formed header map', function() {
    $model = httpForwarderModel();
    $model->headers = ['DD-API-KEY' => '$PP_DATADOG_KEY', 'X-Env' => 'production'];

    expect($model->validate())->toBeTrue();
});

it('rejects a header name that is not an HTTP token', function() {
    $model = httpForwarderModel();
    $model->headers = ['Bad Header' => 'value'];

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('headers'))->not->toBeEmpty();
});

it('rejects a transport-owned header name', function(string $name) {
    $model = httpForwarderModel();
    $model->headers = [$name => 'value'];

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('headers'))->not->toBeEmpty();
})->with([
    'Content-Type',
    'content-length',
    'Host',
    'Transfer-Encoding',
    'Connection',
]);

it('rejects an Authorization header that collides with the auth type', function() {
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_BEARER;
    $model->authToken = 'token';
    $model->headers = ['Authorization' => 'Splunk other-token'];

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('headers'))->not->toBeEmpty();
});

it('allows an Authorization header when the auth type is none', function() {
    // The Splunk HEC scheme: `Authorization: Splunk <token>`, which no
    // generic auth type expresses.
    $model = httpForwarderModel();
    $model->authType = SiemForwarderModel::AUTH_TYPE_NONE;
    $model->headers = ['Authorization' => 'Splunk 00000000-0000-0000-0000-000000000000'];

    expect($model->validate())->toBeTrue();
});

it('rejects an empty header value', function() {
    $model = httpForwarderModel();
    $model->headers = ['X-Empty' => '   '];

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('headers'))->not->toBeEmpty();
});

// =============================================================================
// Syslog framing
// =============================================================================

it('defaults to the RFC 5425 octet-counted framing', function() {
    expect((new SiemForwarderModel())->framing)
        ->toBe(SiemForwarderModel::FRAMING_OCTET_COUNTED);
});

it('accepts both framings', function(string $framing) {
    $model = syslogForwarderModel();
    $model->framing = $framing;

    expect($model->validate())->toBeTrue();
})->with([
    SiemForwarderModel::FRAMING_OCTET_COUNTED,
    SiemForwarderModel::FRAMING_NEWLINE,
]);

it('rejects an unsupported framing', function() {
    $model = syslogForwarderModel();
    $model->framing = 'octet-stuffed';

    expect($model->validate())->toBeFalse()
        ->and($model->getErrors('framing'))->not->toBeEmpty();
});

it('keeps the framing choice through an HTTP round trip', function() {
    // The column is not null, so there is nothing to null out, and holding
    // the value means a forwarder switched back to syslog still frames the
    // way its receiver expects.
    $model = httpForwarderModel();
    $model->framing = SiemForwarderModel::FRAMING_NEWLINE;

    expect($model->toRecordAttributes()['framing'])
        ->toBe(SiemForwarderModel::FRAMING_NEWLINE);
});

// =============================================================================
// Display labels
// =============================================================================

it('labels a syslog forwarder by host and port', function() {
    $model = syslogForwarderModel();

    expect($model->getEndpointLabel())->toBe('siem.example.test:6514')
        ->and($model->getDisplayName())->toBe('siem.example.test:6514');
});

it('labels an HTTP forwarder by URL', function() {
    $model = httpForwarderModel();

    expect($model->getEndpointLabel())->toBe('https://collector.example.test/ingest');
});

it('prefers the name over the endpoint label', function() {
    $model = httpForwarderModel();
    $model->name = 'Datadog';

    expect($model->getDisplayName())->toBe('Datadog');
});

it('labels a brand-new forwarder with an empty string', function() {
    expect((new SiemForwarderModel())->getEndpointLabel())->toBe('');
});
