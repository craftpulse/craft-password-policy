<?php
/**
 * Pest coverage for `ApiTokenService` — the Feature 2 (read-only REST API,
 * Enterprise) Bearer-token write + read path.
 *
 * Pins:
 *
 *  - `issue()` returns the plaintext exactly once and stores ONLY the
 *    SHA-256 hash + an 8-char prefix — never the plaintext.
 *  - `findByToken()` resolves a valid token, touches `lastUsedAt`, and
 *    returns null for an unknown token, an expired token, and an empty
 *    string (uniform null — no existence oracle).
 *  - `revoke()` deletes the row.
 *  - `pruneExpired()` deletes past-expiry tokens, keeps no-expiry + future
 *    tokens.
 *  - The `tokenHash` column never leaks through the model — neither
 *    `fields()`, `toArray()`, nor JSON encoding surface it.
 *
 * The service carries no edition gate (the gate lives on the CP manager +
 * the API controller), so these run on whatever edition the playground is
 * at without elevation.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craftpulse\passwordpolicy\models\ApiTokenModel;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getApiTokens();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_api_tokens}}')
        ->execute();
});

// =============================================================================
// Helpers
// =============================================================================

function tokenRow(int $id): ?array
{
    $row = (new Query())
        ->from('{{%passwordpolicy_api_tokens}}')
        ->where(['id' => $id])
        ->one();

    return $row ?: null;
}

// =============================================================================
// issue() — plaintext once, hash + prefix at rest
// =============================================================================

it('issues a token, stores the hash (not the plaintext) plus a matching prefix', function() {
    $result = $this->service->issue('CI pipeline');

    expect($result)->toHaveKey('token')
        ->and($result)->toHaveKey('model')
        ->and($result['token'])->toBeString()
        ->and($result['model'])->toBeInstanceOf(ApiTokenModel::class);

    $plaintext = $result['token'];
    $model = $result['model'];

    $row = tokenRow($model->id);

    expect($row)->not->toBeNull();

    // The stored hash is the SHA-256 of the plaintext — the plaintext
    // itself is nowhere in the row.
    expect($row['tokenHash'])->toBe(hash('sha256', $plaintext))
        ->and($row['tokenHash'])->not->toBe($plaintext);

    // The prefix is the first 8 chars of the plaintext.
    expect($row['tokenPrefix'])->toBe(substr($plaintext, 0, 8))
        ->and($model->tokenPrefix)->toBe(substr($plaintext, 0, 8));

    // The full plaintext appears in no column of the row.
    foreach ($row as $value) {
        if (is_string($value)) {
            expect($value)->not->toBe($plaintext);
        }
    }
});

it('mints distinct tokens on repeated issue', function() {
    $a = $this->service->issue('a');
    $b = $this->service->issue('b');

    expect($a['token'])->not->toBe($b['token'])
        ->and($a['model']->id)->not->toBe($b['model']->id);
});

// =============================================================================
// findByToken() — resolve, touch, reject
// =============================================================================

it('resolves a valid token and touches lastUsedAt', function() {
    $issued = $this->service->issue('valid');

    $before = tokenRow($issued['model']->id);
    expect($before['lastUsedAt'])->toBeNull();

    $resolved = $this->service->findByToken($issued['token']);

    expect($resolved)->toBeInstanceOf(ApiTokenModel::class)
        ->and($resolved->id)->toBe($issued['model']->id);

    $after = tokenRow($issued['model']->id);
    expect($after['lastUsedAt'])->not->toBeNull();
});

it('returns null for an unknown token', function() {
    $this->service->issue('exists');

    expect($this->service->findByToken('this-token-was-never-issued'))->toBeNull();
});

it('returns null for an empty token string', function() {
    expect($this->service->findByToken(''))->toBeNull();
});

it('returns null for an expired token (uniform with not-found)', function() {
    $issued = $this->service->issue(
        'expired',
        null,
        Carbon::now('UTC')->subDay()->toDateTime(),
    );

    expect($this->service->findByToken($issued['token']))->toBeNull();
});

it('resolves a token whose expiry is still in the future', function() {
    $issued = $this->service->issue(
        'future',
        null,
        Carbon::now('UTC')->addDay()->toDateTime(),
    );

    expect($this->service->findByToken($issued['token']))->not->toBeNull();
});

// =============================================================================
// revoke() + pruneExpired()
// =============================================================================

it('revokes a token by id', function() {
    $issued = $this->service->issue('revoke-me');

    expect($this->service->revoke($issued['model']->id))->toBeTrue()
        ->and(tokenRow($issued['model']->id))->toBeNull()
        ->and($this->service->findByToken($issued['token']))->toBeNull();
});

it('returns false when revoking a non-existent token', function() {
    expect($this->service->revoke(999999))->toBeFalse();
});

it('prunes expired tokens but keeps no-expiry and future tokens', function() {
    $expired = $this->service->issue('expired', null, Carbon::now('UTC')->subDays(2)->toDateTime());
    $future = $this->service->issue('future', null, Carbon::now('UTC')->addDays(2)->toDateTime());
    $noExpiry = $this->service->issue('forever');

    $deleted = $this->service->pruneExpired();

    expect($deleted)->toBe(1)
        ->and(tokenRow($expired['model']->id))->toBeNull()
        ->and(tokenRow($future['model']->id))->not->toBeNull()
        ->and(tokenRow($noExpiry['model']->id))->not->toBeNull();
});

// =============================================================================
// Model never leaks tokenHash
// =============================================================================

it('never exposes tokenHash through fields(), toArray(), or JSON', function() {
    $issued = $this->service->issue('no-leak');
    $model = $issued['model'];

    expect($model->fields())->not->toContain('tokenHash');

    $array = $model->toArray();
    expect($array)->not->toHaveKey('tokenHash');

    $json = json_encode($array);
    expect($json)->not->toContain('tokenHash')
        ->and($json)->not->toContain(hash('sha256', $issued['token']));
});

it('never exposes tokenHash on a model hydrated by getAllTokens()', function() {
    $this->service->issue('listed');

    $models = $this->service->getAllTokens();

    expect($models)->not->toBeEmpty();

    foreach ($models as $model) {
        expect($model->fields())->not->toContain('tokenHash')
            ->and($model->toArray())->not->toHaveKey('tokenHash');
    }
});
