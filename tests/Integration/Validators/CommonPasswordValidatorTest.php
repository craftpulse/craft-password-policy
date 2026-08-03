<?php
/**
 * Pest coverage for `CommonPasswordValidator` — the blocklist matcher.
 * The validator reads a cached word→source hash map keyed by
 * `passwordpolicy_blocklist_word_sources`. Source-aware error messages
 * branch on `'custom'` vs anything-else (treated as common) — cover both
 * branches and a few edge cases the bug-fix sweep never had a chance to
 * trip.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\BlocklistFactory;
use craftpulse\passwordpolicy\validators\CommonPasswordValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new CommonPasswordValidator();

    // Custom-word enforcement is Pro-gated inside `validateValue()` (the
    // custom blocklist editor is a Pro feature). Common-word enforcement
    // stays universal. Pin Pro so the source-aware custom-word tests below
    // exercise the match path; the Lite custom-word suppression is pinned
    // explicitly in its own test.
    $this->originalEdition = PasswordPolicy::$plugin->edition;
    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_PRO;

    PasswordPolicy::$plugin->getBlocklist()->clearCache();
});

afterEach(function() {
    PasswordPolicy::$plugin->edition = $this->originalEdition;
    PasswordPolicy::$plugin->getBlocklist()->clearCache();
});

// =============================================================================
// Empty blocklist — no errors regardless of input
// =============================================================================

it('returns null when the blocklist table is empty', function() {
    expect($this->validator->validateValue('anything'))->toBeNull()
        ->and($this->validator->validateValue(''))->toBeNull()
        ->and($this->validator->validateValue('123456'))->toBeNull();
});

// =============================================================================
// Source-aware messages — common vs custom branches
// =============================================================================

it('rejects a common-source match with the "too common" message', function() {
    BlocklistFactory::commonWord('hunter2');

    $result = $this->validator->validateValue('hunter2');

    expect($result)->not->toBeNull()
        ->and($result[0])->toContain('too common');
});

it('rejects a custom-source match with the "blocked" message', function() {
    BlocklistFactory::customWord('mycompanyname');

    $result = $this->validator->validateValue('mycompanyname');

    expect($result)->not->toBeNull()
        ->and($result[0])->toContain('blocked');
});

it('keeps the messages distinct per source', function() {
    BlocklistFactory::commonWord('common-word');
    BlocklistFactory::customWord('custom-word');

    $commonMessage = $this->validator->validateValue('common-word')[0];
    $customMessage = $this->validator->validateValue('custom-word')[0];

    expect($commonMessage)->not->toBe($customMessage);
});

// =============================================================================
// Case-insensitivity — words stored lowercase, input lowercased pre-lookup
// =============================================================================

it('matches uppercase input against a lowercase blocklist row', function() {
    BlocklistFactory::commonWord('summer2024');

    expect($this->validator->validateValue('SUMMER2024'))->not->toBeNull()
        ->and($this->validator->validateValue('Summer2024'))->not->toBeNull()
        ->and($this->validator->validateValue('summer2024'))->not->toBeNull();
});

it('trims surrounding whitespace before lookup', function() {
    BlocklistFactory::commonWord('trimmed');

    expect($this->validator->validateValue('  trimmed  '))->not->toBeNull();
});

// =============================================================================
// Non-matching input
// =============================================================================

it('returns null for words not in the blocklist', function() {
    BlocklistFactory::commonWord('wordone');
    BlocklistFactory::customWord('wordtwo');

    expect($this->validator->validateValue('wordthree'))->toBeNull();
});

// =============================================================================
// policyId scoping (G6) — default validator filters out per-policy rows
// =============================================================================

it('matches global custom rows but ignores per-policy rows by default', function() {
    // G6 inverts the pre-G6 contract: the validator no longer matches
    // every row in `{{%passwordpolicy_blocklist}}`. With `policyIds = null`
    // (the default — used by Pro/Lite installs and any caller that hasn't
    // resolved a target user), only global rows (`policyId IS NULL`) are
    // visible. Per-policy rows surface only when the validator config
    // includes that policy id.
    $policy = \craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory::custom([
        'minLength' => 12,
    ]);

    BlocklistFactory::customWord('global', null);
    BlocklistFactory::customWord('scoped', $policy->id);

    expect($this->validator->validateValue('global'))->not->toBeNull()
        ->and($this->validator->validateValue('scoped'))->toBeNull();
});

// =============================================================================
// Cache lifecycle — full-table projection cached and invalidated by writes
// =============================================================================

it('caches the full blocklist projection after the first read', function() {
    BlocklistFactory::commonWord('cached');

    // First call populates the cache. Service-level cache key is shared
    // between every per-policy filter combination — single key, in-memory
    // filter on read.
    $this->validator->validateValue('cached');

    $cached = \Craft::$app->getCache()->get('pp:blocklist:full');

    expect($cached)
        ->not->toBeFalse()
        ->toBeArray()
        ->toHaveKey('cached')
        ->and($cached['cached'])->toMatchArray(['source' => 'common', 'policyId' => null]);
});

it('reflects new rows after the cache is cleared', function() {
    BlocklistFactory::commonWord('first');
    $this->validator->validateValue('first'); // primes cache

    BlocklistFactory::customWord('second');
    // Without the BlocklistFactory's cache flush, 'second' would not be
    // visible until TTL expiry. The factory flushes — codify the contract.
    expect($this->validator->validateValue('second'))->not->toBeNull();
});

// =============================================================================
// Edition gate — common enforcement is universal, custom enforcement is Pro+
// =============================================================================

it('enforces common-source matches on every edition', function() {
    // Common-password enforcement is a Lite feature (the `checkCommonPasswords`
    // toggle ships on every edition). The validator must reject a common
    // match identically across editions — no `getIsPro()` gate on this branch.
    BlocklistFactory::commonWord('edition-blind');

    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_LITE;
    $liteResult = $this->validator->validateValue('edition-blind');

    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_PRO;
    $proResult = $this->validator->validateValue('edition-blind');

    expect($liteResult)->not->toBeNull()
        ->and($proResult)->not->toBeNull();
});

it('does not enforce custom-source matches below Pro', function() {
    // The custom blocklist editor is a Pro feature. A Lite install that
    // still holds custom rows (e.g. seeded under Pro then downgraded) must
    // NOT enforce them — otherwise it would enforce a blocklist it can no
    // longer edit. Pro enforces the same row.
    BlocklistFactory::customWord('pro-only-custom');

    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_LITE;
    $liteResult = $this->validator->validateValue('pro-only-custom');

    PasswordPolicy::$plugin->edition = PasswordPolicy::EDITION_PRO;
    $proResult = $this->validator->validateValue('pro-only-custom');

    expect($liteResult)->toBeNull()
        ->and($proResult)->not->toBeNull()
        ->and($proResult[0])->toContain('blocked');
});
