<?php
/**
 * Pest coverage for the per-policy custom blocklist surface (G6) — the
 * Enterprise extension of P1.11. The schema column `policyId` shipped at
 * install time, but the editor + write path land here. This file pins:
 *
 *  - `addCustomWord($word, ?int $policyId)` writes the policyId scope.
 *  - `getCustomWordsForPolicy(int $policyId)` returns only that policy's
 *    rows (global + other-policy rows are filtered out).
 *  - `getWordsForPolicy(?int $policyId)` and `getWordsForPolicies(int[])`
 *    return the merged `[word => source]` projection that the validator
 *    consumes.
 *  - The full-table cache (`pp:blocklist:full`) is invalidated on every
 *    write — adds, removes, seeds.
 *
 * The validator itself is covered separately in
 * `CommonPasswordValidatorPolicyTest`; this file is service-shape only.
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

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getBlocklist();

    // The per-policy custom blocklist editor is Pro+. `addCustomWord()`
    // throws below Pro, so pin Pro for the service-shape tests here.
    $this->originalEdition = PasswordPolicy::$plugin->edition;
    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_PRO;

    $this->service->clearCache();
});

afterEach(function() {
    PasswordPolicy::$plugin->edition = $this->originalEdition;
    $this->service->clearCache();
});

// =============================================================================
// addCustomWord — policyId scope writes
// =============================================================================

it('writes a global custom row when policyId is null (default)', function() {
    $this->service->addCustomWord('global-word');

    $row = (new \craft\db\Query())
        ->select(['word', 'source', 'policyId'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['word' => 'global-word'])
        ->one();

    expect($row)->toBe([
        'word' => 'global-word',
        'source' => 'custom',
        'policyId' => null,
    ]);
});

it('writes a per-policy custom row when policyId is set', function() {
    $policy = PolicyFactory::custom(['minLength' => 12]);
    $this->service->addCustomWord('per-policy-word', $policy->id);

    $row = (new \craft\db\Query())
        ->select(['word', 'source', 'policyId'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['word' => 'per-policy-word'])
        ->one();

    expect($row)->toMatchArray([
        'word' => 'per-policy-word',
        'source' => 'custom',
    ])->and((int)$row['policyId'])->toBe((int)$policy->id);
});

it('throws when policyId references a non-existent policy', function() {
    expect(fn() => $this->service->addCustomWord('orphan', 999_999_999))
        ->toThrow(\InvalidArgumentException::class);
});

it('returns false on a duplicate word regardless of scope', function() {
    // The schema enforces a single-column unique index on `word`, so
    // a word can exist EITHER as a global entry OR as a per-policy
    // entry, never both. The duplicate guard mirrors the index so the
    // service never throws an integrity violation up to the caller.
    $policyA = PolicyFactory::custom();
    $policyB = PolicyFactory::custom();

    expect($this->service->addCustomWord('dup-global'))->toBeTrue()
        ->and($this->service->addCustomWord('dup-global', $policyA->id))->toBeFalse()
        ->and($this->service->addCustomWord('dup-scoped', $policyA->id))->toBeTrue()
        ->and($this->service->addCustomWord('dup-scoped'))->toBeFalse()
        ->and($this->service->addCustomWord('dup-scoped', $policyB->id))->toBeFalse();
});

// =============================================================================
// getCustomWordsForPolicy — scoped reads
// =============================================================================

it('returns only the rows scoped to the given policy', function() {
    $policyA = PolicyFactory::custom(['handle' => 'policyA' . bin2hex(random_bytes(2))]);
    $policyB = PolicyFactory::custom(['handle' => 'policyB' . bin2hex(random_bytes(2))]);

    BlocklistFactory::customWord('global-only', null);
    BlocklistFactory::customWord('a-only', $policyA->id);
    BlocklistFactory::customWord('b-only', $policyB->id);

    $rows = $this->service->getCustomWordsForPolicy((int)$policyA->id);
    $words = array_column($rows, 'word');

    expect($words)->toBe(['a-only']);
});

it('returns an empty array when the policy has no per-policy entries', function() {
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('global-only', null);

    expect($this->service->getCustomWordsForPolicy((int)$policy->id))->toBe([]);
});

// =============================================================================
// getAllCustomWords — global-only after G6 (per-policy excluded)
// =============================================================================

it('excludes per-policy rows from the global custom list', function() {
    // P1.11 returned every custom row; G6 narrows the global editor to
    // global-only rows so the per-policy rows surface only via the
    // policy edit screen. Pin the new contract.
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('global-row', null);
    BlocklistFactory::customWord('scoped-row', $policy->id);

    $words = array_column($this->service->getAllCustomWords(), 'word');

    expect($words)->toBe(['global-row']);
});

// =============================================================================
// getWordsForPolicy / getWordsForPolicies — merged projection
// =============================================================================

it('returns global rows when policyId is null', function() {
    BlocklistFactory::commonWord('common-x');
    BlocklistFactory::customWord('global-x', null);

    $merged = $this->service->getWordsForPolicy(null);

    expect($merged)
        ->toHaveKey('common-x')
        ->toHaveKey('global-x');
});

it('returns global + that policy rows for getWordsForPolicy(int)', function() {
    $policyA = PolicyFactory::custom();
    $policyB = PolicyFactory::custom();

    BlocklistFactory::customWord('global-y', null);
    BlocklistFactory::customWord('a-y', $policyA->id);
    BlocklistFactory::customWord('b-y', $policyB->id);

    $merged = $this->service->getWordsForPolicy((int)$policyA->id);

    expect($merged)
        ->toHaveKey('global-y')
        ->toHaveKey('a-y')
        ->and($merged)->not->toHaveKey('b-y');
});

it('merges multiple policies in getWordsForPolicies', function() {
    $policyA = PolicyFactory::custom();
    $policyB = PolicyFactory::custom();
    $policyC = PolicyFactory::custom();

    BlocklistFactory::customWord('global-z', null);
    BlocklistFactory::customWord('a-z', $policyA->id);
    BlocklistFactory::customWord('b-z', $policyB->id);
    BlocklistFactory::customWord('c-z', $policyC->id);

    $merged = $this->service->getWordsForPolicies([(int)$policyA->id, (int)$policyB->id]);

    expect($merged)
        ->toHaveKey('global-z')
        ->toHaveKey('a-z')
        ->toHaveKey('b-z')
        ->and($merged)->not->toHaveKey('c-z');
});

// =============================================================================
// Cache invalidation — full-table key flushes on every write
// =============================================================================

it('invalidates pp:blocklist:full on addCustomWord', function() {
    \Craft::$app->getCache()->set('pp:blocklist:full', ['stale' => ['source' => 'custom', 'policyId' => null]], 3600);

    $this->service->addCustomWord('fresh-word');

    expect(\Craft::$app->getCache()->get('pp:blocklist:full'))->toBeFalse();
});

it('caches the full projection across getWordsForPolicy calls', function() {
    BlocklistFactory::commonWord('cache-probe');

    $this->service->getWordsForPolicy(null); // primes
    $cached = \Craft::$app->getCache()->get('pp:blocklist:full');

    expect($cached)
        ->toBeArray()
        ->toHaveKey('cache-probe')
        ->and($cached['cache-probe'])->toMatchArray([
            'source' => 'common',
            'policyId' => null,
        ]);
});

it('reflects new rows after each write — cache flush handshake', function() {
    BlocklistFactory::commonWord('first');
    expect($this->service->getWordsForPolicy(null))->toHaveKey('first');

    $this->service->addCustomWord('second');
    expect($this->service->getWordsForPolicy(null))
        ->toHaveKey('first')
        ->toHaveKey('second');
});
