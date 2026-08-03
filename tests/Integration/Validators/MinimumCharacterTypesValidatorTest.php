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
 * @link      https://craft-pulse.com
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

it('counts an accented lowercase letter as lowercase', function() {
    // `é` (U+00E9) is `\p{Ll}` — the Unicode-aware lowercase class.
    // Pre-fix the symbol regex `[^a-zA-Z0-9]` matched it and `é` counted
    // as a symbol; an admin requiring "1 symbol" let `password123é`
    // through. Post-fix `é` counts as lowercase, and the same password
    // satisfies a "1 lowercase" requirement — but does NOT satisfy a
    // "1 symbol" requirement. Canary for the gap-2 fix landed in 5.2.0.
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('é'))->toBeNull();
});

it('counts a Greek lowercase letter as lowercase', function() {
    // `λ` (U+03BB) is `\p{Ll}`. Same story as `é` — categorised as a
    // letter, not a symbol.
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('λ'))->toBeNull();
});

it('counts a Greek uppercase letter as uppercase', function() {
    // `Λ` (U+039B) is `\p{Lu}` — the Unicode-aware uppercase class. Pre-
    // fix it failed `[A-Z]` and counted as a symbol; post-fix it counts
    // as uppercase.
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('Λ'))->toBeNull();
});

it('counts emoji as symbols', function() {
    // `🎉` (U+1F389) is `\p{So}` (other symbol) — outside `\p{L}`,
    // `\p{N}`, and `\p{Z}`, so it falls through to the residual symbol
    // class. Pinned because it was the leading non-letter case in the
    // gap report.
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('🎉'))->toBeNull();
});

it('does not count Unicode digits as the digit class', function() {
    // `²` (U+00B2) is `\p{No}` (other number). The digit class is
    // intentionally `[0-9]` — "digit" in password-policy context means
    // an Arabic numeral the user typed off the number row, not every
    // Unicode numeral. `²` also fails the residual symbol class because
    // `\p{N}` is excluded. So it's effectively uncounted: a password
    // containing only `²` satisfies zero classes. Codify so a future
    // change to either class surfaces as a deliberate flip.
    $this->settings->minimumCharacterTypes = 1;

    expect($this->validator->validateValue('²'))->not->toBeNull();
});

it('treats `password123é` as lowercase + digits: symbol still missing', function() {
    // Two distinct classes: lowercase (`p`,`a`,`s`,`w`,`o`,`r`,`d`,`é`)
    // + digits (`1`,`2`,`3`). With required=2 it passes; with required=3
    // it fails because there's no symbol or uppercase. Documents the
    // user-visible consequence of the symbol-class fix: an accented
    // letter no longer satisfies a "needs at least one symbol" rule.
    $this->settings->minimumCharacterTypes = 2;
    expect($this->validator->validateValue('password123é'))->toBeNull();

    $this->settings->minimumCharacterTypes = 3;
    expect($this->validator->validateValue('password123é'))->not->toBeNull();
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

// =============================================================================
// Resolved per-user override — public property wins over global
// =============================================================================

it('uses the resolved minimumCharacterTypes property over the global setting', function() {
    // Global says 1; the resolved per-group policy says 3. A 2-class password
    // must fail because the validator honors the threaded property, not the
    // (laxer) global value re-read from settings.
    $this->settings->minimumCharacterTypes = 1;

    $validator = new MinimumCharacterTypesValidator(['minimumCharacterTypes' => 3]);

    // Lowercase + digit = 2 of 4 < 3.
    expect($validator->validateValue('abcd1234'))->not->toBeNull()
        // 3 classes satisfies the resolved requirement.
        ->and($validator->validateValue('Abcd1234'))->toBeNull();
});

it('falls back to the global setting when the property is null', function() {
    $this->settings->minimumCharacterTypes = 3;

    $validator = new MinimumCharacterTypesValidator(); // property null

    // Lowercase + digit = 2 of 4 < 3 (global).
    expect($validator->validateValue('abcd1234'))->not->toBeNull();
});
