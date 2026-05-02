<?php
/**
 * Pest coverage for `MinimumCharacterTypesValidator` — the "X of 4
 * character types" complexity mode (Pro). The validator reads
 * `minimumCharacterTypes` off the plugin's live `SettingsModel` each call,
 * so each test mutates that property and restores the original value
 * afterwards. State on the model is in-memory only — the per-test
 * transaction wrapper handles DB isolation, but property mutation needs
 * its own teardown.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\validators\MinimumCharacterTypesValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new MinimumCharacterTypesValidator();
    $this->settings = PasswordPolicy::$plugin->getSettings();
    $this->originalRequirement = $this->settings->minimumCharacterTypes;
});

afterEach(function() {
    $this->settings->minimumCharacterTypes = $this->originalRequirement;
});

// =============================================================================
// Disabled mode — `minimumCharacterTypes <= 0`
// =============================================================================

it('returns null when the requirement is zero (mode disabled)', function() {
    $this->settings->minimumCharacterTypes = 0;

    expect($this->validator->validateValue(''))->toBeNull()
        ->and($this->validator->validateValue('a'))->toBeNull()
        ->and($this->validator->validateValue('Abc1!'))->toBeNull();
});

it('returns null when the requirement is negative', function() {
    // Defensive — the SettingsModel typed this as `int` and the UI clamps
    // to 0..4, but the validator's guard is `<= 0` so a negative value
    // also short-circuits.
    $this->settings->minimumCharacterTypes = -1;

    expect($this->validator->validateValue('a'))->toBeNull();
});

// =============================================================================
// Boundary cases — exact match between supplied types and required count
// =============================================================================

it('accepts when the password meets the required count exactly', function() {
    $this->settings->minimumCharacterTypes = 2;

    // Lowercase + digit = 2 of 4.
    expect($this->validator->validateValue('abcd1234'))->toBeNull();
});

it('accepts when the password exceeds the required count', function() {
    $this->settings->minimumCharacterTypes = 2;

    // Lowercase + uppercase + digit + symbol = 4 of 4 ≥ 2.
    expect($this->validator->validateValue('Abcd1!ef'))->toBeNull();
});

it('rejects when the password falls short of the required count', function() {
    $this->settings->minimumCharacterTypes = 3;

    // Lowercase + digit = 2 of 4 < 3.
    expect($this->validator->validateValue('abcd1234'))->not->toBeNull();
});

it('rejects when only one character class is present', function() {
    $this->settings->minimumCharacterTypes = 2;

    expect($this->validator->validateValue('abcdefgh'))->not->toBeNull();
});

it('rejects an empty string when the requirement is greater than zero', function() {
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue(''))->not->toBeNull();
});

// =============================================================================
// Each character class branch
// =============================================================================

it('counts uppercase letters as a class', function() {
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('ABCD'))->toBeNull();
});

it('counts lowercase letters as a class', function() {
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('abcd'))->toBeNull();
});

it('counts digits as a class', function() {
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('1234'))->toBeNull();
});

it('counts symbols as a class', function() {
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('!@#$'))->toBeNull();
});

// =============================================================================
// Quirks — Unicode + symbol class definition
// =============================================================================

it('counts non-ASCII letters as the symbol class', function() {
    // The symbol regex is `[^a-zA-Z0-9]`, so anything outside the ASCII
    // alphanumerics — including Latin-1, accented letters, and emoji —
    // qualifies as a symbol. Codifies the current matcher; if the
    // validator ever switches to Unicode-aware character classes this
    // assertion becomes the canary.
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('é'))->toBeNull();
});

it('does not double-count classes when a class repeats', function() {
    // Three lowercase letters still only give one class.
    $this->settings->minimumCharacterTypes = 2;

    expect($this->validator->validateValue('abcdef'))->not->toBeNull();
});

it('requires four distinct classes when set to four', function() {
    $this->settings->minimumCharacterTypes = 4;

    expect($this->validator->validateValue('Abcdef1'))->not->toBeNull()
        ->and($this->validator->validateValue('Abcdef1!'))->toBeNull();
});
