<?php
/**
 * Pest coverage for `AuditLogService::canonicalize()` — the byte-stable
 * JSON encoder that drives the audit-log SHA-256 chain.
 *
 * The verifier (G2) recomputes hashes by feeding stored payloads through
 * this same method. If the output drifts (e.g. a future PHP upgrade flips
 * the `JSON_UNESCAPED_*` defaults, or someone "tidies up" the recursive
 * sort), every chain in the wild breaks invisibly. These tests pin the
 * contract:
 *
 *  - Alphabetical key order (recursive).
 *  - `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` flags.
 *  - `null` preserved (not stripped).
 *  - Booleans encoded as `true`/`false` (not coerced to `1`/`0`).
 *  - Integers bare (not quoted).
 *  - One golden-string regression test as a tripwire on silent flag
 *    drift across PHP minor versions.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\services\AuditLogService;

// =============================================================================
// Key order — same input shape encoded identically regardless of source order
// =============================================================================

it('produces identical output for re-ordered input keys', function() {
    $a = AuditLogService::canonicalize(['z' => 1, 'a' => 2]);
    $b = AuditLogService::canonicalize(['a' => 2, 'z' => 1]);

    expect($a)->toBe($b);
    expect($a)->toBe('{"a":2,"z":1}');
});

it('sorts nested array keys recursively', function() {
    $a = AuditLogService::canonicalize([
        'outer' => ['z' => 1, 'a' => 2],
        'b' => 'second',
        'a' => 'first',
    ]);
    $b = AuditLogService::canonicalize([
        'a' => 'first',
        'b' => 'second',
        'outer' => ['a' => 2, 'z' => 1],
    ]);

    expect($a)->toBe($b);
    expect($a)->toBe('{"a":"first","b":"second","outer":{"a":2,"z":1}}');
});

// =============================================================================
// Null preservation — null values must NOT be stripped
// =============================================================================

it('preserves null values rather than stripping them', function() {
    $output = AuditLogService::canonicalize(['k' => null, 'present' => 1]);

    expect($output)->toBe('{"k":null,"present":1}');
});

// =============================================================================
// Boolean encoding — true/false not coerced to 1/0
// =============================================================================

it('encodes booleans as true and false (not 1 and 0)', function() {
    $output = AuditLogService::canonicalize(['enabled' => true, 'disabled' => false]);

    expect($output)->toBe('{"disabled":false,"enabled":true}');
});

// =============================================================================
// Integer passthrough — bare numerics, not quoted strings
// =============================================================================

it('encodes integers as bare numerics', function() {
    $output = AuditLogService::canonicalize(['count' => 42, 'big' => 9007199254740992]);

    expect($output)->toBe('{"big":9007199254740992,"count":42}');
});

// =============================================================================
// Unicode passthrough — JSON_UNESCAPED_UNICODE keeps the original code points
// =============================================================================

it('emits Unicode code points unescaped', function() {
    $output = AuditLogService::canonicalize(['name' => 'café résumé']);

    // Without JSON_UNESCAPED_UNICODE PHP would emit é sequences.
    expect($output)->toBe('{"name":"café résumé"}');
});

// =============================================================================
// Forward-slash passthrough — JSON_UNESCAPED_SLASHES keeps slashes literal
// =============================================================================

it('emits forward slashes unescaped', function() {
    $output = AuditLogService::canonicalize(['url' => 'https://example.test/path']);

    // Without JSON_UNESCAPED_SLASHES PHP would emit `https:\/\/example.test\/path`.
    expect($output)->toBe('{"url":"https://example.test/path"}');
});

// =============================================================================
// Golden-string regression — full audit-shape payload, hard-coded reference
// =============================================================================

it('matches the golden canonical string for a representative payload', function() {
    $payload = [
        'changedByUserId' => 42,
        'dateCreated' => '2026-05-07T08:12:01Z',
        'details' => ['violationType' => 'expired', 'reason' => 'Force reset'],
        'event' => 'force_reset',
        'ipHash' => 'abc123',
        'outcome' => 'success',
        'source' => 'admin',
        'uid' => '5b3f-uid',
        'userId' => 17,
        'userIdentifier' => 'hmac-of-email',
    ];

    $expected = '{"changedByUserId":42,'
        . '"dateCreated":"2026-05-07T08:12:01Z",'
        . '"details":{"reason":"Force reset","violationType":"expired"},'
        . '"event":"force_reset",'
        . '"ipHash":"abc123",'
        . '"outcome":"success",'
        . '"source":"admin",'
        . '"uid":"5b3f-uid",'
        . '"userId":17,'
        . '"userIdentifier":"hmac-of-email"}';

    expect(AuditLogService::canonicalize($payload))->toBe($expected);
});
