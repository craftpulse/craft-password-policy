<?php
/**
 * Pest coverage for `BlocklistService` — the CRUD + lookup layer over
 * `passwordpolicy_blocklist`. The `CommonPasswordValidator` consumes this
 * service through a static cache key, so every mutating call here also
 * flushes the cache. Tests verify both the service's read/write behavior
 * and the cache-flush handshake the validator depends on.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\BlocklistFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getBlocklist();
    $this->service->clearCache();
});

afterEach(function() {
    $this->service->clearCache();
});

// =============================================================================
// addCustomWord — insert + dedup + normalisation
// =============================================================================

it('adds a custom word and reports success', function() {
    $added = $this->service->addCustomWord('TopSecret');

    expect($added)->toBeTrue()
        ->and($this->service->isWordBlocked('TopSecret'))->toBe('custom')
        ->and($this->service->isWordBlocked('topsecret'))->toBe('custom');
});

it('lowercases and trims custom words on insert', function() {
    $this->service->addCustomWord('  PassWord  ');

    // Read back via isBlocked() (the admin "check a word" tool path) to
    // confirm the row landed lowercased + trimmed.
    expect($this->service->isBlocked('password'))->toBe(['blocked' => true, 'source' => 'custom'])
        ->and($this->service->isBlocked('PASSWORD'))->toBe(['blocked' => true, 'source' => 'custom']);
});

it('rejects a duplicate custom word as a no-op', function() {
    $this->service->addCustomWord('alpha');
    $second = $this->service->addCustomWord('alpha');

    expect($second)->toBeFalse();
});

it('rejects a duplicate custom word that collides on case', function() {
    // Normalisation runs before the duplicate check, so 'Alpha' and
    // 'ALPHA' are both treated as 'alpha' for the existence test.
    $this->service->addCustomWord('Alpha');
    $second = $this->service->addCustomWord('ALPHA');

    expect($second)->toBeFalse();
});

it('rejects an empty word as a no-op', function() {
    expect($this->service->addCustomWord(''))->toBeFalse()
        ->and($this->service->addCustomWord('   '))->toBeFalse();
});

// =============================================================================
// removeCustomWord
// =============================================================================

it('removes a custom word by ID', function() {
    BlocklistFactory::customWord('todelete');
    $allBefore = $this->service->getAllCustomWords();
    $id = (int)$allBefore[0]['id'];

    $this->service->removeCustomWord($id);

    expect($this->service->isWordBlocked('todelete'))->toBeNull();
});

it('does not remove common entries via removeCustomWord', function() {
    // The DELETE filters on `source = 'custom'` — calling removeCustomWord()
    // with a 'common' row's ID is a no-op. Codifies the safety net.
    BlocklistFactory::commonWord('protected');

    $commonId = (int)\Craft::$app->getDb()->createCommand(
        "SELECT id FROM {{%passwordpolicy_blocklist}} WHERE word = 'protected'"
    )->queryScalar();

    $this->service->removeCustomWord($commonId);

    expect($this->service->isWordBlocked('protected'))->toBe('common');
});

// =============================================================================
// isBlocked / isWordBlocked — lookup paths
// =============================================================================

it('returns blocked=false for an absent word', function() {
    expect($this->service->isBlocked('nonexistent'))
        ->toBe(['blocked' => false, 'source' => null]);
});

it('returns blocked=true with source for a common word', function() {
    BlocklistFactory::commonWord('correcthorse');

    expect($this->service->isBlocked('correcthorse'))
        ->toBe(['blocked' => true, 'source' => 'common']);
});

it('returns blocked=true with source for a custom word', function() {
    BlocklistFactory::customWord('battery');

    expect($this->service->isBlocked('battery'))
        ->toBe(['blocked' => true, 'source' => 'custom']);
});

it('treats an empty isBlocked input as not blocked', function() {
    BlocklistFactory::customWord('something');

    // Defensive — the AJAX "check a word" endpoint shouldn't issue a
    // SELECT for an empty input.
    expect($this->service->isBlocked(''))
        ->toBe(['blocked' => false, 'source' => null])
        ->and($this->service->isBlocked('   '))
        ->toBe(['blocked' => false, 'source' => null]);
});

it('lookups are case-insensitive', function() {
    BlocklistFactory::customWord('mixedcase');

    expect($this->service->isBlocked('MIXEDCASE'))
        ->toBe(['blocked' => true, 'source' => 'custom'])
        ->and($this->service->isBlocked('MixedCase'))
        ->toBe(['blocked' => true, 'source' => 'custom']);
});

// =============================================================================
// getAllCustomWords — only `source = 'custom'`
// =============================================================================

it('returns only custom words, ordered by word ASC', function() {
    BlocklistFactory::commonWord('zzcommon');
    BlocklistFactory::customWord('charlie');
    BlocklistFactory::customWord('alpha');
    BlocklistFactory::customWord('bravo');

    $words = $this->service->getAllCustomWords();

    expect($words)->toHaveCount(3)
        ->and(array_column($words, 'word'))->toBe(['alpha', 'bravo', 'charlie']);
});

it('returns an empty array when no custom words exist', function() {
    BlocklistFactory::commonWord('lonely');

    expect($this->service->getAllCustomWords())->toBe([]);
});

// =============================================================================
// getCommonCount + getLastUpdated
// =============================================================================

it('counts only common rows, ignoring custom', function() {
    BlocklistFactory::commonWord('one');
    BlocklistFactory::commonWord('two');
    BlocklistFactory::commonWord('three');
    BlocklistFactory::customWord('custom1');
    BlocklistFactory::customWord('custom2');

    expect($this->service->getCommonCount())->toBe(3);
});

it('returns null from getLastUpdated when no common rows exist', function() {
    BlocklistFactory::customWord('only-custom');

    expect($this->service->getLastUpdated())->toBeNull();
});

it('returns the most recent common dateCreated from getLastUpdated', function() {
    BlocklistFactory::commonWord('seeded');

    expect($this->service->getLastUpdated())->not->toBeNull();
});

// =============================================================================
// Cache flush handshake — service mutations must invalidate the validator
// =============================================================================

it('clearCache flushes the cached word→source map', function() {
    // Prime the cache by calling the validator's read path indirectly:
    // the service-level lookup doesn't hit the cache, but the validator
    // does. Tested in CommonPasswordValidatorTest.
    \Craft::$app->getCache()->set('passwordpolicy_blocklist_word_sources', ['poisoned' => 'custom'], 3600);

    $this->service->clearCache();

    expect(\Craft::$app->getCache()->get('passwordpolicy_blocklist_word_sources'))->toBeFalse();
});

it('addCustomWord invalidates the validator cache', function() {
    \Craft::$app->getCache()->set('passwordpolicy_blocklist_word_sources', ['stale' => 'custom'], 3600);

    $this->service->addCustomWord('fresh');

    expect(\Craft::$app->getCache()->get('passwordpolicy_blocklist_word_sources'))->toBeFalse();
});

it('removeCustomWord invalidates the validator cache', function() {
    BlocklistFactory::customWord('removeme');
    $id = (int)\Craft::$app->getDb()->createCommand(
        "SELECT id FROM {{%passwordpolicy_blocklist}} WHERE word = 'removeme'"
    )->queryScalar();

    \Craft::$app->getCache()->set('passwordpolicy_blocklist_word_sources', ['stale' => 'custom'], 3600);

    $this->service->removeCustomWord($id);

    expect(\Craft::$app->getCache()->get('passwordpolicy_blocklist_word_sources'))->toBeFalse();
});

// =============================================================================
// seedCommonPasswords — bundled SecLists data file
// =============================================================================

it('seeds common passwords from the bundled data file', function() {
    $count = $this->service->seedCommonPasswords();

    // The bundled file is the SecLists 10k list — exact count is brittle to
    // assert, but >0 + a known entry is enough to prove the seed ran.
    expect($count)->toBeGreaterThan(0)
        ->and($this->service->isWordBlocked('123456'))->toBe('common');
});

it('replaces existing common entries on re-seed', function() {
    // Seed once, modify a row, re-seed: the modified row should disappear
    // because seedCommonPasswords() deletes-then-inserts the common slice.
    $this->service->seedCommonPasswords();

    \Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_blocklist}}', [
            'word' => 'totallyunique-marker-' . bin2hex(random_bytes(2)),
            'source' => 'common',
            'policyId' => null,
            'dateCreated' => \Carbon\Carbon::now('UTC')->format('Y-m-d H:i:s'),
        ])
        ->execute();

    $countBefore = $this->service->getCommonCount();
    $this->service->seedCommonPasswords();
    $countAfter = $this->service->getCommonCount();

    // After re-seed, the marker row is gone and the count matches the file
    // size exactly — countAfter is < countBefore by 1.
    expect($countAfter)->toBe($countBefore - 1);
});

it('preserves custom entries on re-seed', function() {
    BlocklistFactory::customWord('keepme');
    $this->service->seedCommonPasswords();

    expect($this->service->isWordBlocked('keepme'))->toBe('custom');
});
