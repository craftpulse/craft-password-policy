<?php
/**
 * Pest coverage for `CommonPasswordValidator` per-policy filtering (G6).
 *
 * The pre-G6 validator matched every row in `{{%passwordpolicy_blocklist}}`;
 * G6 introduced the `policyIds` config so callers (UserRules,
 * ValidationController) scope the validator to global rows + the
 * authenticated user's resolved per-policy rows. The general validator
 * test file pins the cache lifecycle and source-aware messages — this
 * file pins the `policyIds` filter contract:
 *
 *  - `policyIds = null` (default): global rows only.
 *  - `policyIds = [int]`: global rows + that policy's rows.
 *  - `policyIds = [int, int]`: global rows + both policies' rows.
 *  - Other policies' rows are NEVER visible.
 *
 * Source-aware messages still flow through the source field — global
 * "common" rows emit "too common", per-policy "custom" rows emit
 * "blocked".
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\BlocklistFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\validators\CommonPasswordValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    // Custom-word enforcement is Pro-gated inside `validateValue()`; the
    // per-policy filter contract pinned here is itself a Pro+/Enterprise
    // surface, so run at Pro so the custom rows actually match.
    $this->originalEdition = PasswordPolicy::$plugin->edition;
    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_PRO;

    PasswordPolicy::$plugin->getBlocklist()->clearCache();
});

afterEach(function() {
    PasswordPolicy::$plugin->edition = $this->originalEdition;
    PasswordPolicy::$plugin->getBlocklist()->clearCache();
});

// =============================================================================
// policyIds default — global only
// =============================================================================

it('rejects only global-blocked words when policyIds is null (default)', function() {
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('default-global', null);
    BlocklistFactory::customWord('default-scoped', $policy->id);

    $validator = new CommonPasswordValidator();

    expect($validator->validateValue('default-global'))->not->toBeNull()
        ->and($validator->validateValue('default-scoped'))->toBeNull();
});

it('rejects only global-blocked words when policyIds is an empty array', function() {
    // Empty array is the explicit "I'm filtering, but no policy applies"
    // case — the validator still matches global rows but never any
    // per-policy rows. Pin separately from the null default so the
    // contract is explicit.
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('empty-global', null);
    BlocklistFactory::customWord('empty-scoped', $policy->id);

    $validator = new CommonPasswordValidator(['policyIds' => []]);

    expect($validator->validateValue('empty-global'))->not->toBeNull()
        ->and($validator->validateValue('empty-scoped'))->toBeNull();
});

// =============================================================================
// policyIds with a single policy
// =============================================================================

it('rejects global + scoped words when policyIds includes the policy', function() {
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('single-global', null);
    BlocklistFactory::customWord('single-scoped', $policy->id);

    $validator = new CommonPasswordValidator(['policyIds' => [(int)$policy->id]]);

    expect($validator->validateValue('single-global'))->not->toBeNull()
        ->and($validator->validateValue('single-scoped'))->not->toBeNull();
});

// =============================================================================
// policyIds with multiple policies
// =============================================================================

it('rejects words from any policy in the multi-policy set', function() {
    $policyA = PolicyFactory::custom();
    $policyB = PolicyFactory::custom();
    $policyC = PolicyFactory::custom();

    BlocklistFactory::customWord('multi-global', null);
    BlocklistFactory::customWord('multi-a', $policyA->id);
    BlocklistFactory::customWord('multi-b', $policyB->id);
    BlocklistFactory::customWord('multi-c', $policyC->id);

    $validator = new CommonPasswordValidator([
        'policyIds' => [(int)$policyA->id, (int)$policyB->id],
    ]);

    expect($validator->validateValue('multi-global'))->not->toBeNull()
        ->and($validator->validateValue('multi-a'))->not->toBeNull()
        ->and($validator->validateValue('multi-b'))->not->toBeNull()
        ->and($validator->validateValue('multi-c'))->toBeNull();
});

// =============================================================================
// Source-aware messages still apply per row
// =============================================================================

it('emits the per-policy "blocked" message for a custom-source per-policy hit', function() {
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('blocked-token', $policy->id);

    $validator = new CommonPasswordValidator(['policyIds' => [(int)$policy->id]]);
    $result = $validator->validateValue('blocked-token');

    expect($result)->not->toBeNull()
        ->and($result[0])->toContain('blocked');
});

it('emits the global "too common" message for a common-source hit', function() {
    BlocklistFactory::commonWord('common-token');

    $validator = new CommonPasswordValidator();
    $result = $validator->validateValue('common-token');

    expect($result)->not->toBeNull()
        ->and($result[0])->toContain('too common');
});
