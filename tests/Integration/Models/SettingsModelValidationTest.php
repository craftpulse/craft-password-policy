<?php
/**
 * Pest coverage for `SettingsModel::defineRules()` additions and the
 * `fields()` alias strip.
 *
 * Pins three correctness-misc fixes:
 *  - `expiryAmount` now validates as a positive integer (was unvalidated;
 *    a 0 or negative value would have flowed into `DateInterval`
 *    construction downstream and either reset every user or crashed).
 *    The rule is `when`-guarded so a null amount (expiry disabled) stays
 *    valid.
 *  - `siemCircuitCooldownSeconds` / `siemCircuitFailureThreshold` now
 *    validate with the same `min` floors as their webhook siblings —
 *    they shipped without a rule.
 *  - `fields()` strips the legacy `pwned` / `pwnedFailMode` aliases so a
 *    `toArray()` round-trip can't leak them back onto the read surface.
 *
 * No DB needed — the model validates entirely in memory. The Integration
 * suite still wraps it in a transaction so adjacent tests stay clean.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\SettingsModel;

// =============================================================================
// expiryAmount
// =============================================================================

it('accepts a null expiryAmount (expiry disabled)', function() {
    $model = new SettingsModel();
    $model->expiryAmount = null;

    expect($model->validate(['expiryAmount']))->toBeTrue();
});

it('accepts a positive expiryAmount', function() {
    $model = new SettingsModel();
    $model->expiryAmount = 30;

    expect($model->validate(['expiryAmount']))->toBeTrue();
});

it('rejects a zero expiryAmount', function() {
    $model = new SettingsModel();
    $model->expiryAmount = 0;

    expect($model->validate(['expiryAmount']))->toBeFalse()
        ->and($model->hasErrors('expiryAmount'))->toBeTrue();
});

it('rejects a negative expiryAmount', function() {
    $model = new SettingsModel();
    $model->expiryAmount = -5;

    expect($model->validate(['expiryAmount']))->toBeFalse()
        ->and($model->hasErrors('expiryAmount'))->toBeTrue();
});

// =============================================================================
// SIEM circuit-breaker
// =============================================================================

it('rejects a sub-1 siemCircuitCooldownSeconds', function() {
    $model = new SettingsModel();
    $model->siemCircuitCooldownSeconds = 0;

    expect($model->validate(['siemCircuitCooldownSeconds']))->toBeFalse()
        ->and($model->hasErrors('siemCircuitCooldownSeconds'))->toBeTrue();
});

it('rejects a sub-1 siemCircuitFailureThreshold', function() {
    $model = new SettingsModel();
    $model->siemCircuitFailureThreshold = 0;

    expect($model->validate(['siemCircuitFailureThreshold']))->toBeFalse()
        ->and($model->hasErrors('siemCircuitFailureThreshold'))->toBeTrue();
});

it('accepts valid SIEM circuit-breaker values', function() {
    $model = new SettingsModel();
    $model->siemCircuitCooldownSeconds = 300;
    $model->siemCircuitFailureThreshold = 5;

    expect($model->validate(['siemCircuitCooldownSeconds', 'siemCircuitFailureThreshold']))->toBeTrue();
});

// =============================================================================
// fields() alias strip
// =============================================================================

it('strips the legacy pwned aliases from fields()', function() {
    $model = new SettingsModel();
    $fields = $model->fields();

    expect($fields)->not->toHaveKey('pwned')
        ->and($fields)->not->toHaveKey('pwnedFailMode');
});

it('does not leak the legacy aliases through a toArray() round-trip', function() {
    $model = new SettingsModel();
    $array = $model->toArray();

    expect($array)->not->toHaveKey('pwned')
        ->and($array)->not->toHaveKey('pwnedFailMode')
        ->and($array)->toHaveKey('hibp');
});
