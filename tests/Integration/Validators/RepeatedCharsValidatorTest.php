<?php
/**
 * Pest coverage for `RepeatedCharsValidator` — codifies the validator's
 * behavior around the `(.)\1{2,}/u` regex (3+ identical Unicode code
 * points in a row). Lives under `Integration/` so the rejection branch's
 * `Craft::t()` call has a booted application to translate against.
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
// Rejection cases — three or more identical code points
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

it('is case-sensitive: `Aaa` does not trip the rule', function() {
    // The `/u` modifier makes the matcher Unicode-aware, but it does NOT
    // case-fold. `A` (U+0041) differs from `a` (U+0061), so only `aa`
    // (two identical code points) sits under the threshold. If we ever
    // case-fold the input, this expectation flips and the test should be
    // the canary.
    expect($this->validator->validateValue('Aaa'))->toBeNull();
});

it('rejects the lowercase form of the same triple', function() {
    expect($this->validator->validateValue('aaa'))->not->toBeNull();
});

it('rejects three identical Greek code points', function() {
    // `α` is U+03B1 — two-byte UTF-8. Without the `/u` modifier the regex
    // operated on raw bytes (`CE B1 CE B1 CE B1` — no byte repeats three
    // times in a row) and `ααα` slipped through. With `/u` the matcher
    // reads code points, three U+03B1 in sequence trip the rule the same
    // way `aaa` does. Canary for the Unicode-aware fix landed in 5.2.0.
    expect($this->validator->validateValue('ααα'))->not->toBeNull();
});

it('rejects three identical Cyrillic code points', function() {
    // `е` is U+0435 — two-byte UTF-8. Same byte-vs-codepoint distinction
    // as the Greek case. Pinned because Cyrillic users were the second
    // most-affected locale in the gap report.
    expect($this->validator->validateValue('еее'))->not->toBeNull();
});

it('rejects three identical emoji code points', function() {
    // `🎉` is U+1F389 — four-byte UTF-8. Three of them form twelve bytes
    // with no single byte repeating three times in a row, so the
    // pre-fix matcher passed it. Codepoint-aware matching catches it.
    expect($this->validator->validateValue('🎉🎉🎉'))->not->toBeNull();
});
