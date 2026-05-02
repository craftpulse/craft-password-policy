<?php
/**
 * Pest coverage for `SequentialCharsValidator` — codifies the validator's
 * current behavior against ascending/descending ASCII runs and configured
 * keyboard rows. Lives under `Integration/` because the validator's
 * rejection branch calls `Craft::t()`, which requires a booted Craft
 * application — the bootstrap supplies one, so each test rolls back
 * cleanly via the `TestCase` transaction wrapper.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\validators\SequentialCharsValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new SequentialCharsValidator();
});

// =============================================================================
// Happy path
// =============================================================================

it('accepts non-sequential passwords', function() {
    expect($this->validator->validateValue('Hx9$mK2p'))->toBeNull();
});

it('accepts a single character', function() {
    // _hasAsciiSequence early-returns when length < SEQUENCE_LENGTH.
    expect($this->validator->validateValue('a'))->toBeNull();
});

it('accepts two-character runs under the threshold', function() {
    // SEQUENCE_LENGTH = 3 — two-char ascending pairs stay below the line.
    expect($this->validator->validateValue('ab'))->toBeNull();
});

it('accepts an empty string', function() {
    // Length 0 < SEQUENCE_LENGTH and no keyboard substring can match.
    expect($this->validator->validateValue(''))->toBeNull();
});

// =============================================================================
// ASCII ascending sequences
// =============================================================================

it('rejects ascending letter runs at the threshold', function() {
    expect($this->validator->validateValue('abc'))->not->toBeNull();
});

it('rejects ascending letter runs longer than the threshold', function() {
    expect($this->validator->validateValue('abcd'))->not->toBeNull();
});

it('rejects ascending number runs', function() {
    expect($this->validator->validateValue('123'))->not->toBeNull();
});

it('rejects sequences embedded inside otherwise random passwords', function() {
    expect($this->validator->validateValue('myabcpass'))->not->toBeNull();
});

it('rejects ASCII-adjacency sequences that look benign', function() {
    // Documented quirk in T3.1: `pqr` triggers because ASCII 112,113,114
    // are three consecutive ascending code points.
    expect($this->validator->validateValue('pqr'))->not->toBeNull();
});

// =============================================================================
// ASCII descending sequences
// =============================================================================

it('rejects descending letter runs', function() {
    expect($this->validator->validateValue('cba'))->not->toBeNull();
});

it('rejects descending number runs', function() {
    expect($this->validator->validateValue('321'))->not->toBeNull();
});

it('rejects descending runs embedded in passwords', function() {
    expect($this->validator->validateValue('mycbapass'))->not->toBeNull();
});

// =============================================================================
// Case + non-adjacent breaks
// =============================================================================

it('is case-insensitive on ASCII letters', function() {
    // strtolower() runs first — `aBc` → `abc`.
    expect($this->validator->validateValue('aBc'))->not->toBeNull();
});

it('does not flag mixed-case uppercase sequences via raw bytes', function() {
    // Sanity check the lowering: `ABC` lowers to `abc` and trips the rule
    // even though the uppercase ASCII range also forms a sequence.
    expect($this->validator->validateValue('ABC'))->not->toBeNull();
});

it('treats non-adjacent ASCII jumps as breaks', function() {
    // `b`→`!` is not a +/-1 ASCII step, so the ascending counter resets.
    expect($this->validator->validateValue('ab!cd'))->toBeNull();
});

it('catches a sequence even when later chars break the run', function() {
    // `abc` already crosses the threshold inside `abcxyz`; later resets
    // can't undo the early return.
    expect($this->validator->validateValue('abcxyz'))->not->toBeNull();
});

// =============================================================================
// Keyboard sequences
// =============================================================================

it('rejects top-row keyboard sequences', function() {
    expect($this->validator->validateValue('myqwepass'))->not->toBeNull();
});

it('rejects home-row keyboard sequences', function() {
    expect($this->validator->validateValue('myasdpass'))->not->toBeNull();
});

it('rejects bottom-row keyboard sequences', function() {
    expect($this->validator->validateValue('myzxcpass'))->not->toBeNull();
});

it('rejects longer keyboard substrings', function() {
    // `werty` is a 5-char top-row substring — multiple 3-char chunks of
    // it (wer/ert/rty) match the configured `qwertyuiop` row.
    expect($this->validator->validateValue('iwertyu'))->not->toBeNull();
});

it('rejects reversed keyboard sequences', function() {
    expect($this->validator->validateValue('myewqpass'))->not->toBeNull();
});

it('rejects number-row sequences via the keyboard list', function() {
    // `890` is keyboard-only — ASCII for 8,9,0 is 56,57,48 which breaks
    // ascending. Verifies the keyboard branch stands on its own.
    expect($this->validator->validateValue('foo890bar'))->not->toBeNull();
});
