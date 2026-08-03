<?php
/**
 * Pest coverage for `PasswordService::generatePattern()` and
 * `generateMessage()` — the helpers that build the per-policy complexity
 * regex and human-readable description string from the cases/numbers/
 * symbols toggles. `UserRules::defineRules()` feeds the result into Yii's
 * `match` validator, so these helpers ARE the complexity contract.
 *
 * The service's `init()` caches a reference to the plugin's live
 * `SettingsModel`, so each test mutates the singleton, runs the helper,
 * and restores the snapshot in `afterEach`. Length rules
 * (min/max) live on Yii's built-in `string` validator; testing Yii
 * core would just be retesting upstream, so this file scopes to the
 * behavior we own.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getPasswords();
    $this->settings = PasswordPolicy::$plugin->getSettings();
    $this->snapshot = [
        'cases' => $this->settings->cases,
        'numbers' => $this->settings->numbers,
        'symbols' => $this->settings->symbols,
    ];
});

afterEach(function() {
    foreach ($this->snapshot as $key => $value) {
        $this->settings->$key = $value;
    }
});

// =============================================================================
// generatePattern() — empty / disabled
// =============================================================================

it('returns the empty start anchor when every toggle is off', function() {
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    expect($this->service->generatePattern())->toBe('/^/');
});

it('matches anything when no toggles are active', function() {
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    expect((bool)preg_match($this->service->generatePattern(), 'whatever'))->toBeTrue()
        ->and((bool)preg_match($this->service->generatePattern(), ''))->toBeTrue();
});

// =============================================================================
// generatePattern() — single-toggle branches
// =============================================================================

it('requires both cases when the cases toggle is on', function() {
    $this->settings->cases = true;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    $pattern = $this->service->generatePattern();

    expect((bool)preg_match($pattern, 'aB'))->toBeTrue()
        ->and((bool)preg_match($pattern, 'abcdef'))->toBeFalse()
        ->and((bool)preg_match($pattern, 'ABCDEF'))->toBeFalse();
});

it('requires a digit when the numbers toggle is on', function() {
    $this->settings->cases = false;
    $this->settings->numbers = true;
    $this->settings->symbols = false;

    $pattern = $this->service->generatePattern();

    expect((bool)preg_match($pattern, 'abc1'))->toBeTrue()
        ->and((bool)preg_match($pattern, 'abcdef'))->toBeFalse();
});

it('requires a symbol when the symbols toggle is on', function() {
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = true;

    $pattern = $this->service->generatePattern();

    expect((bool)preg_match($pattern, 'abc!'))->toBeTrue()
        ->and((bool)preg_match($pattern, 'abcdef'))->toBeFalse()
        ->and((bool)preg_match($pattern, 'abc123'))->toBeFalse();
});

// =============================================================================
// generatePattern() — combined toggles
// =============================================================================

it('combines cases and numbers when both toggles are on', function() {
    $this->settings->cases = true;
    $this->settings->numbers = true;
    $this->settings->symbols = false;

    $pattern = $this->service->generatePattern();

    expect((bool)preg_match($pattern, 'Ab1'))->toBeTrue()
        ->and((bool)preg_match($pattern, 'ab1'))->toBeFalse()
        ->and((bool)preg_match($pattern, 'AB1'))->toBeFalse()
        ->and((bool)preg_match($pattern, 'Abc'))->toBeFalse();
});

it('combines cases, numbers, and symbols when every toggle is on', function() {
    $this->settings->cases = true;
    $this->settings->numbers = true;
    $this->settings->symbols = true;

    $pattern = $this->service->generatePattern();

    expect((bool)preg_match($pattern, 'Ab1!'))->toBeTrue()
        ->and((bool)preg_match($pattern, 'Ab1'))->toBeFalse()
        ->and((bool)preg_match($pattern, 'Ab!'))->toBeFalse()
        ->and((bool)preg_match($pattern, 'A1!'))->toBeFalse();
});

// =============================================================================
// generateMessage() — formatting
// =============================================================================

it('returns an empty message when every toggle is off', function() {
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    expect($this->service->generateMessage())->toBe('');
});

it('returns the lone clause without an "and" when only one toggle is on', function() {
    $this->settings->cases = false;
    $this->settings->numbers = true;
    $this->settings->symbols = false;

    // No comma to replace — `preg_replace` runs but matches nothing.
    expect($this->service->generateMessage())->toBe('a number');
});

it('joins multiple clauses with " and " before the last item', function() {
    // The implementation joins with `, ` then rewrites the last comma to
    // ` and `, so two clauses get a single ` and ` separator.
    $this->settings->cases = true;
    $this->settings->numbers = true;
    $this->settings->symbols = false;

    $message = $this->service->generateMessage();

    expect($message)->toContain(' and ')
        ->and($message)->toContain('a lowercase character, an uppercase character')
        ->and($message)->toContain('a number');
});

// =============================================================================
// Resolved-settings override — per-group policy wins over global
// =============================================================================

it('builds the pattern from a supplied settings model, not the global one', function() {
    // Global has every toggle off — its pattern matches anything. A resolved
    // per-group policy with `numbers` on must still require a digit when
    // passed explicitly. Proves the per-group complexity override is honored
    // rather than silently re-reading the global model from init().
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    $resolved = new SettingsModel();
    $resolved->cases = false;
    $resolved->numbers = true;
    $resolved->symbols = false;

    $pattern = $this->service->generatePattern($resolved);

    expect((bool)preg_match($pattern, 'abc1'))->toBeTrue()
        ->and((bool)preg_match($pattern, 'abcdef'))->toBeFalse()
        // Global pattern (no arg) would match the digit-less string.
        ->and((bool)preg_match($this->service->generatePattern(), 'abcdef'))->toBeTrue();
});

it('builds the message from a supplied settings model, not the global one', function() {
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    $resolved = new SettingsModel();
    $resolved->cases = false;
    $resolved->numbers = true;
    $resolved->symbols = false;

    expect($this->service->generateMessage($resolved))->toBe('a number')
        // Global message (no arg) is empty — every toggle is off.
        ->and($this->service->generateMessage())->toBe('');
});

it('rewrites only the trailing separator into " and " when three clauses join', function() {
    $this->settings->cases = true;
    $this->settings->numbers = true;
    $this->settings->symbols = true;

    $message = $this->service->generateMessage();

    // Cases clause itself embeds a comma ("a lowercase character, an
    // uppercase character"), then `, ` joins clauses, and only the
    // last comma rewrites to ` and `. Verifies we only touch the trailing
    // separator — earlier commas inside the cases clause stay intact.
    //
    // Quirk codified: the rewrite replaces the bare `,` (not `, `), so
    // the separator becomes ` and  ` (two spaces) before the last
    // clause. Cosmetic only — captured here so a future cleanup pass
    // doesn't silently regress the format.
    expect(substr_count($message, ' and '))->toBe(1)
        ->and($message)->toEndWith(' and  a special character.')
        ->and($message)->toContain('a lowercase character, an uppercase character');
});
