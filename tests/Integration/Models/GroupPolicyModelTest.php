<?php
/**
 * Pest coverage for `GroupPolicyModel::mergeWithGlobal()` — the per-policy
 * field merger. Booleans are NOT touched at this layer — they're resolved
 * cross-policy by `PolicyResolverService` (see `booleanOverrideFields()`).
 * Codify the contract: numeric minimums max-wins, numeric maximums min-
 * wins, expiration shortest-wins, HIBP fail-mode fail-closed-wins,
 * complexity-mode individual-wins, and booleans pass through untouched.
 *
 * The two previously-skipped tests in this file were waiting on E2's
 * resolver coverage — E3.3 unblocks them by codifying the post-refactor
 * "booleans bypass mergeWithGlobal" contract directly here, and the
 * cross-policy boolean resolution proper lands in `PolicyResolverService`
 * tests (E3.4).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\GroupPolicyModel;
use craftpulse\passwordpolicy\models\SettingsModel;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->global = new SettingsModel();
});

// =============================================================================
// Inheritance — null overrides pass the global through
// =============================================================================

it('inherits global values when group policy is all null', function() {
    $group = new GroupPolicyModel();
    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minLength)->toBe($this->global->minLength)
        ->and($merged->maxLength)->toBe($this->global->maxLength)
        ->and($merged->cases)->toBe($this->global->cases);
});

// =============================================================================
// Integer minimums — max wins (more restrictive)
// =============================================================================

it('applies highest value for integer minimums', function() {
    $this->global->minLength = 8;

    $group = new GroupPolicyModel();
    $group->minLength = 12;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minLength)->toBe(12);
});

it('keeps global when global integer minimum is higher', function() {
    $this->global->minLength = 16;

    $group = new GroupPolicyModel();
    $group->minLength = 8;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minLength)->toBe(16);
});

// =============================================================================
// Integer maximums — min wins (more restrictive), but 0 means "no cap"
// =============================================================================

it('applies lowest non-zero value for integer maximums', function() {
    $this->global->maxLength = 128;

    $group = new GroupPolicyModel();
    $group->maxLength = 64;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->maxLength)->toBe(64);
});

it('treats zero maxLength as no limit', function() {
    $this->global->maxLength = 0;

    $group = new GroupPolicyModel();
    $group->maxLength = 128;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->maxLength)->toBe(128);
});

it('treats zero group maxLength as no group override', function() {
    // The merge guard is `$this->maxLength > 0` — a zero on the group means
    // "no cap from this policy"; don't strengthen the global.
    $this->global->maxLength = 64;

    $group = new GroupPolicyModel();
    $group->maxLength = 0;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->maxLength)->toBe(64);
});

// =============================================================================
// Booleans — NOT merged at this layer (codifies tri-state Option A
// architecture decision; cross-policy resolution happens in resolver)
// =============================================================================

it('does not let group true overwrite global true via mergeWithGlobal', function() {
    // The 2026-04-29 refactor moved boolean cross-policy resolution into
    // `PolicyResolverService::resolveForUser()`. The model layer no longer
    // touches booleans — calling `mergeWithGlobal` always returns the
    // global value unchanged for boolean fields. Pin that contract.
    $this->global->cases = true;

    $group = new GroupPolicyModel();
    $group->cases = true;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->cases)->toBe(true);
});

it('does not let group false weaken global true', function() {
    // Pre-refactor this would have been "single-group exemption: group's
    // explicit false honored against global true". Post-refactor the
    // resolver handles this — `mergeWithGlobal` leaves the boolean
    // untouched. Cross-policy "any explicit true wins over any explicit
    // false" is codified in PolicyResolverService tests.
    $this->global->cases = true;

    $group = new GroupPolicyModel();
    $group->cases = false;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->cases)->toBe(true);
});

it('does not let group true overrule global false', function() {
    // Symmetric — group `true` against global `false` doesn't propagate
    // through this layer either.
    $this->global->cases = false;

    $group = new GroupPolicyModel();
    $group->cases = true;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->cases)->toBe(false);
});

it('passes global through for every boolean override field', function(string $field) {
    // Tri-state matrix — for each boolean field that participates in
    // cross-policy resolution (`GroupPolicyModel::booleanOverrideFields()`),
    // confirm `mergeWithGlobal` is a no-op regardless of the group value.
    foreach ([true, false, null] as $globalValue) {
        $globalCopy = clone $this->global;
        $globalCopy->{$field} = $globalValue ?? false; // SettingsModel uses bool not ?bool

        foreach ([true, false, null] as $groupValue) {
            $group = new GroupPolicyModel();
            $group->{$field} = $groupValue;

            $merged = $group->mergeWithGlobal($globalCopy);

            // Whatever the group says, merged keeps the global value.
            expect($merged->{$field})->toBe($globalCopy->{$field});
        }
    }
})->with(GroupPolicyModel::booleanOverrideFields());

it('exposes the canonical boolean override field list', function() {
    // Sanity pin — if a future refactor adds a boolean to the policy
    // surface but forgets to register it here, this assertion catches the
    // drift. Cross-references with `PolicyResolverService::resolveForUser`
    // pre-pass.
    expect(GroupPolicyModel::booleanOverrideFields())->toBe([
        'cases',
        'numbers',
        'symbols',
        'hibp',
        'checkSequentialChars',
        'checkRepeatedChars',
        'checkContextual',
        'checkCommonPasswords',
    ]);
});

// =============================================================================
// String enum modes — fail-closed and individual win (more restrictive)
// =============================================================================

it('upgrades hibpFailMode to closed when group sets closed', function() {
    $this->global->hibpFailMode = 'open';

    $group = new GroupPolicyModel();
    $group->hibpFailMode = 'closed';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->hibpFailMode)->toBe('closed');
});

it('keeps hibpFailMode closed when global is closed and group is open', function() {
    $this->global->hibpFailMode = 'closed';

    $group = new GroupPolicyModel();
    $group->hibpFailMode = 'open';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->hibpFailMode)->toBe('closed');
});

it('keeps hibpFailMode open when both are open', function() {
    $this->global->hibpFailMode = 'open';

    $group = new GroupPolicyModel();
    $group->hibpFailMode = 'open';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->hibpFailMode)->toBe('open');
});

it('applies individual complexity mode over minimum', function() {
    $this->global->complexityMode = 'minimum';

    $group = new GroupPolicyModel();
    $group->complexityMode = 'individual';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->complexityMode)->toBe('individual');
});

it('keeps individual complexity mode when group is minimum', function() {
    $this->global->complexityMode = 'individual';

    $group = new GroupPolicyModel();
    $group->complexityMode = 'minimum';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->complexityMode)->toBe('individual');
});

// =============================================================================
// Expiration period — shortest interval wins (most restrictive)
// =============================================================================

it('applies shortest expiration period when group is shorter', function() {
    $this->global->expiryAmount = 180;
    $this->global->expiryPeriod = 'day';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 90;
    $group->expiryPeriod = 'day';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(90)
        ->and($merged->expiryPeriod)->toBe('day');
});

it('keeps global when global expiration is shorter', function() {
    $this->global->expiryAmount = 30;
    $this->global->expiryPeriod = 'day';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 90;
    $group->expiryPeriod = 'day';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(30);
});

it('compares expiration across mismatched periods (months vs days)', function() {
    // 2 months ≈ 60 days, 90 days = 90 days — group wins (shorter).
    $this->global->expiryAmount = 90;
    $this->global->expiryPeriod = 'day';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 2;
    $group->expiryPeriod = 'month';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(2)
        ->and($merged->expiryPeriod)->toBe('month');
});

it('compares expiration across week vs day', function() {
    // 1 week = 7 days; group is 5 days — group wins.
    $this->global->expiryAmount = 1;
    $this->global->expiryPeriod = 'week';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 5;
    $group->expiryPeriod = 'day';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(5)
        ->and($merged->expiryPeriod)->toBe('day');
});

it('inherits group expiration when global has none', function() {
    // Global with no expiry treats global days as PHP_INT_MAX, so any
    // group expiry is shorter and wins.
    $this->global->expiryAmount = null;
    $this->global->expiryPeriod = 'day';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 90;
    $group->expiryPeriod = 'day';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(90);
});

// =============================================================================
// passwordHistoryCount + minimumCharacterTypes — max wins
// =============================================================================

it('applies highest value for password history count', function() {
    $this->global->passwordHistoryCount = 5;

    $group = new GroupPolicyModel();
    $group->passwordHistoryCount = 12;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->passwordHistoryCount)->toBe(12);
});

it('applies highest value for minimumCharacterTypes', function() {
    $this->global->minimumCharacterTypes = 2;

    $group = new GroupPolicyModel();
    $group->minimumCharacterTypes = 4;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minimumCharacterTypes)->toBe(4);
});

// =============================================================================
// Immutability — `mergeWithGlobal` must not mutate the input
// =============================================================================

it('does not mutate the global settings model', function() {
    $this->global->minLength = 8;

    $group = new GroupPolicyModel();
    $group->minLength = 12;

    $group->mergeWithGlobal($this->global);

    expect($this->global->minLength)->toBe(8);
});

it('does not mutate the group policy model', function() {
    $group = new GroupPolicyModel();
    $group->minLength = 12;
    $group->maxLength = 128;
    $group->expiryAmount = 90;
    $group->expiryPeriod = 'day';

    $group->mergeWithGlobal($this->global);

    expect($group->minLength)->toBe(12)
        ->and($group->maxLength)->toBe(128)
        ->and($group->expiryAmount)->toBe(90)
        ->and($group->expiryPeriod)->toBe('day');
});
