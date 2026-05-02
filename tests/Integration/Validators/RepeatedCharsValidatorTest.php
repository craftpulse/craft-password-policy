<?php
/**
 * Pest coverage for `RepeatedCharsValidator` — codifies the validator's
 * current behavior around the `(.)\1{2,}` regex (3+ identical bytes in a
 * row). Lives under `Integration/` so the rejection branch's `Craft::t()`
 * call has a booted application to translate against.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\validators\RepeatedCharsValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new RepeatedCharsValidator();
});

// =============================================================================
// Happy path
// =============================================================================

it('accepts random passwords', function() {
    expect($this->validator->validateValue('Hx9$mK2p'))->toBeNull();
});

it('accepts alternating characters', function() {
    expect($this->validator->validateValue('ababab'))->toBeNull();
});

it('accepts an empty string', function() {
    // preg_match against '' returns 0 — the regex requires three bytes.
    expect($this->validator->validateValue(''))->toBeNull();
});

it('accepts two repeated characters', function() {
    // SEQUENCE threshold is 3 — `\1{2,}` means TWO MORE matches, so two
    // total identical bytes is below the line.
    expect($this->validator->validateValue('myaapass'))->toBeNull();
});

// =============================================================================
// Rejection cases — three or more identical bytes
// =============================================================================

it('rejects three repeated lowercase letters', function() {
    expect($this->validator->validateValue('myaaapass'))->not->toBeNull();
});

it('rejects three repeated digits', function() {
    expect($this->validator->validateValue('my111pass'))->not->toBeNull();
});

it('rejects three repeated symbols', function() {
    expect($this->validator->validateValue('my!!!pass'))->not->toBeNull();
});

it('rejects four or more repeated characters', function() {
    expect($this->validator->validateValue('myaaaapass'))->not->toBeNull();
});

it('rejects an all-same-character password', function() {
    expect($this->validator->validateValue('aaaaaaaa'))->not->toBeNull();
});

it('rejects when the run sits at the start of the password', function() {
    expect($this->validator->validateValue('zzzpass'))->not->toBeNull();
});

it('rejects when the run sits at the end of the password', function() {
    expect($this->validator->validateValue('passzzz'))->not->toBeNull();
});

// =============================================================================
// Case sensitivity + Unicode quirks
// =============================================================================

it('is case-sensitive — `Aaa` does not trip the rule', function() {
    // Documented current behavior. The regex `(.)\1{2,}` matches identical
    // bytes; `A` (0x41) differs from `a` (0x61) so only `aa` (two bytes)
    // sits under the threshold. If we ever case-fold the input, this
    // expectation flips and the test should be the canary.
    expect($this->validator->validateValue('Aaa'))->toBeNull();
});

it('rejects the lowercase form of the same triple', function() {
    expect($this->validator->validateValue('aaa'))->not->toBeNull();
});

it('treats multibyte runs as byte-level, not codepoint-level', function() {
    // `α` is two bytes (0xCE 0xB1). Three Greek alphas form an alternating
    // byte stream `CE B1 CE B1 CE B1` — no byte repeats three times in a
    // row, so the validator does NOT reject. Codifies the current
    // byte-level matcher; if we ever switch to multibyte-aware checking,
    // flip this expectation.
    expect($this->validator->validateValue('ααα'))->toBeNull();
});
