<?php
/**
 * Pest coverage for `SettingsModel`'s four-hook legacy alias —
 * `attributes()`, `canGetProperty()`, `canSetProperty()`, `__get()`,
 * `__set()`. Pins the C2 fix from commit 9691541: the 5.1.1-era code
 * had at least one of the four hooks missing, so `pwned: true` in a
 * static `config/password-policy.php` silently failed.
 *
 * The full chain matters because `Plugin::setSettings()` calls
 * `Model::setAttributes()`, which uses `canSetProperty()` to filter
 * unknown attribute names. Without `canSetProperty('pwned')` returning
 * true, the `__set()` override never runs — `setAttributes` skips the
 * key as "not assignable". Without `attributes()` listing the legacy
 * keys, `toArray()` round-trips lose them. All four hooks have to
 * agree.
 *
 * Each test covers one hook in isolation, plus an end-to-end test
 * that drives the full chain via `setAttributes()` (the production
 * boot path for file-based config).
 *
 * No DB needed — the model is pure PHP and the test runs entirely in
 * memory. The Integration suite still wraps it in a transaction so
 * the DB state stays clean for adjacent tests.
 *
 * Plan a path away from this alias for 5.4 — already noted in plan.md
 * P4. This phase pins current behavior so the alias removal in 5.4 is
 * provably backwards-incompatible only for sites that ignored two
 * minor versions of deprecation warnings.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\SettingsModel;
use yii\log\Logger;

// =============================================================================
// Setup — fresh model per test
// =============================================================================

beforeEach(function() {
    $this->model = new SettingsModel();
});

// =============================================================================
// attributes() — list extension
// =============================================================================

it('lists pwned and pwnedFailMode in attributes()', function() {
    $attrs = $this->model->attributes();

    expect($attrs)->toContain('pwned')
        ->and($attrs)->toContain('pwnedFailMode');
});

it('still lists the canonical hibp + hibpFailMode in attributes()', function() {
    // Belt-and-braces: the alias additions don't shadow the parent's
    // canonical attribute discovery. Both names coexist.
    $attrs = $this->model->attributes();

    expect($attrs)->toContain('hibp')
        ->and($attrs)->toContain('hibpFailMode');
});

// =============================================================================
// canGetProperty / canSetProperty — Yii's mass-assignment gates
// =============================================================================

it('reports canGetProperty(pwned) as true', function() {
    expect($this->model->canGetProperty('pwned'))->toBeTrue();
});

it('reports canGetProperty(pwnedFailMode) as true', function() {
    expect($this->model->canGetProperty('pwnedFailMode'))->toBeTrue();
});

it('reports canSetProperty(pwned) as true', function() {
    expect($this->model->canSetProperty('pwned'))->toBeTrue();
});

it('reports canSetProperty(pwnedFailMode) as true', function() {
    expect($this->model->canSetProperty('pwnedFailMode'))->toBeTrue();
});

it('still reports canGetProperty(hibp) as true via parent', function() {
    expect($this->model->canGetProperty('hibp'))->toBeTrue();
});

it('rejects an unrelated unknown property via canGetProperty()', function() {
    // Sanity check — the override's `if` guard is narrow; everything
    // else falls through to the parent which honours actual property
    // visibility.
    expect($this->model->canGetProperty('thisIsNotAProperty'))->toBeFalse();
});

// =============================================================================
// __set — direct property writes flow to the canonical attribute
// =============================================================================

it('writes pwned through to hibp on direct assignment', function() {
    $this->model->pwned = true;

    expect($this->model->hibp)->toBeTrue();
});

it('writes false pwned through to hibp', function() {
    $this->model->hibp = true; // start non-default
    $this->model->pwned = false;

    expect($this->model->hibp)->toBeFalse();
});

it('coerces non-bool pwned values through (bool) cast', function() {
    // The `__set` override casts via `(bool)` — pin the contract so
    // a string like 'yes' or '1' from a file-config flows correctly.
    $this->model->pwned = 1;
    expect($this->model->hibp)->toBeTrue();

    $this->model->pwned = 0;
    expect($this->model->hibp)->toBeFalse();

    $this->model->pwned = '1';
    expect($this->model->hibp)->toBeTrue();

    $this->model->pwned = '';
    expect($this->model->hibp)->toBeFalse();
});

it('writes pwnedFailMode through to hibpFailMode on direct assignment', function() {
    $this->model->pwnedFailMode = 'closed';

    expect($this->model->hibpFailMode)->toBe('closed');
});

it('coerces non-string pwnedFailMode values through (string) cast', function() {
    // Same as the bool cast — production code may receive an enum or
    // a typed value. The cast keeps the property type stable.
    $this->model->pwnedFailMode = 'closed';
    expect($this->model->hibpFailMode)->toBe('closed');

    $this->model->pwnedFailMode = 'open';
    expect($this->model->hibpFailMode)->toBe('open');
});

// =============================================================================
// __get — direct property reads reflect the canonical attribute
// =============================================================================

it('reads pwned as a reflection of hibp', function() {
    $this->model->hibp = true;
    expect($this->model->pwned)->toBeTrue();

    $this->model->hibp = false;
    expect($this->model->pwned)->toBeFalse();
});

it('reads pwnedFailMode as a reflection of hibpFailMode', function() {
    $this->model->hibpFailMode = 'closed';
    expect($this->model->pwnedFailMode)->toBe('closed');

    $this->model->hibpFailMode = 'open';
    expect($this->model->pwnedFailMode)->toBe('open');
});

// =============================================================================
// setAttributes() — the production boot path for file-based config
// =============================================================================

it('flows pwned through setAttributes() to hibp', function() {
    // Production path: `Plugin::setSettings()` calls
    // `Model::setAttributes()`, which checks `canSetProperty()` per key,
    // then dispatches via `__set()`. All four hooks have to cooperate.
    $this->model->setAttributes(['pwned' => true], false);

    expect($this->model->hibp)->toBeTrue()
        ->and($this->model->pwned)->toBeTrue();
});

it('flows pwnedFailMode through setAttributes() to hibpFailMode', function() {
    $this->model->setAttributes(['pwnedFailMode' => 'closed'], false);

    expect($this->model->hibpFailMode)->toBe('closed')
        ->and($this->model->pwnedFailMode)->toBe('closed');
});

it('flows both legacy keys through a combined setAttributes() call', function() {
    $this->model->setAttributes([
        'pwned' => true,
        'pwnedFailMode' => 'closed',
    ], false);

    expect($this->model->hibp)->toBeTrue()
        ->and($this->model->hibpFailMode)->toBe('closed');
});

it('flows the legacy keys alongside canonical keys without collision', function() {
    // A migration-window config might carry both — the new `hibp` line
    // alongside an older `pwned` line. Setting both should not throw.
    // Yii applies attributes in array order; the test pins what the
    // current implementation does (last-write-wins via __set chain).
    $this->model->setAttributes([
        'hibp' => false,
        'pwned' => true, // wins because it's last
    ], false);

    expect($this->model->hibp)->toBeTrue();
});

// =============================================================================
// Deprecation warning — Yii log channel `password-policy`
// =============================================================================

it('emits a deprecation warning on the password-policy channel when pwned is written', function() {
    // Snapshot the logger's message buffer before triggering the write
    // so the assertion isn't polluted by earlier setup-phase log lines.
    $before = count(Craft::getLogger()->messages);

    $this->model->pwned = true;

    $messages = array_slice(Craft::getLogger()->messages, $before);

    // Filter to warning-level messages on the `password-policy` category.
    // Yii log message tuple: [message, level, category, time, traces, memory].
    $deprecation = array_values(array_filter(
        $messages,
        fn(array $m): bool => $m[1] === Logger::LEVEL_WARNING && $m[2] === 'password-policy',
    ));

    expect($deprecation)->not->toBeEmpty();
});

it('emits a deprecation warning on the password-policy channel when pwnedFailMode is written', function() {
    $before = count(Craft::getLogger()->messages);

    $this->model->pwnedFailMode = 'closed';

    $messages = array_slice(Craft::getLogger()->messages, $before);

    $deprecation = array_values(array_filter(
        $messages,
        fn(array $m): bool => $m[1] === Logger::LEVEL_WARNING && $m[2] === 'password-policy',
    ));

    expect($deprecation)->not->toBeEmpty();
});

it('does not emit a deprecation warning when canonical hibp is written', function() {
    // The deprecation warning should fire ONLY for the legacy keys.
    // Canonical writes go through Yii's parent `__set` and produce no
    // password-policy-channel warning.
    $before = count(Craft::getLogger()->messages);

    $this->model->hibp = true;

    $messages = array_slice(Craft::getLogger()->messages, $before);

    $deprecation = array_values(array_filter(
        $messages,
        fn(array $m): bool => $m[1] === Logger::LEVEL_WARNING && $m[2] === 'password-policy',
    ));

    expect($deprecation)->toBeEmpty();
});

// =============================================================================
// Unrelated property writes still go through the parent
// =============================================================================

it('routes non-legacy property writes through the parent __set', function() {
    // Sanity check — the override's `if` guards are narrow; canonical
    // properties still flow through Yii's `Model::__set` so type
    // validation, magic-property logic, etc. all keep working.
    $this->model->minLength = 16;

    expect($this->model->minLength)->toBe(16);
});

it('throws on assigning an unknown property name via __set (parent behavior)', function() {
    // The override's narrow guards mean every other unknown property
    // still hits Yii's parent `Model::__set`, which throws
    // `UnknownPropertyException`. Pinned so a future broadening of
    // the alias surface (e.g. catching every legacy key) makes itself
    // visible here.
    $this->model->aPropertyThatDoesntExist = 'x';
})->throws(\yii\base\UnknownPropertyException::class);

// =============================================================================
// getAttributes() — read surface excludes legacy aliases by default
// =============================================================================
//
// The aliases live in `attributes()` so file-based config load
// (`config/password-policy.php` with `pwned: true`) survives
// `setAttributes()`'s safe-attribute check. They must NOT leak into the
// default `getAttributes()` read — `SettingsController::actionSave()`
// merges existing settings with the submitted form, then hands the
// result to `Plugins::savePluginSettings()` which calls
// `setAttributes($all, false)`. If `getAttributes()` returned `pwned`
// (mirroring the stale pre-save hibp via `__get`), the alias's
// `__set` would overwrite the freshly-set canonical `hibp` during
// the iteration — silently reverting every HIBP toggle save.
//
// 2026-05-22 Phase H smoke test S1.3 caught this in the browser.

it('excludes pwned and pwnedFailMode from default getAttributes() output', function() {
    $values = $this->model->getAttributes();

    expect($values)->not->toHaveKey('pwned')
        ->and($values)->not->toHaveKey('pwnedFailMode');
});

it('still includes the canonical hibp and hibpFailMode in default getAttributes() output', function() {
    $values = $this->model->getAttributes();

    expect($values)->toHaveKey('hibp')
        ->and($values)->toHaveKey('hibpFailMode');
});

it('returns the legacy alias when explicitly requested by name', function() {
    // Back-compat carve-out — callers that explicitly ask for `pwned`
    // still get it via the `__get` alias, so any external integration
    // that reads the legacy key by name keeps working.
    $this->model->hibp = true;
    $values = $this->model->getAttributes(['pwned']);

    expect($values)->toHaveKey('pwned')
        ->and($values['pwned'])->toBeTrue();
});

it('survives the actionSave round-trip when hibp toggles from false to true', function() {
    // The exact regression that S1.3 caught: read existing attributes,
    // merge with a submitted form that sets hibp=true, run setAttributes
    // on the merged array. Without the getAttributes() override, the
    // stale `pwned` carried over from existing would overwrite hibp
    // back to false at the end of the setAttributes iteration.
    $this->model->hibp = false;
    $this->model->hibpFailMode = 'open';

    $existing = $this->model->getAttributes();
    $submitted = ['hibp' => '1'];
    $merged = array_merge($existing, $submitted);

    $this->model->setAttributes($merged, false);

    expect($this->model->hibp)->toBeTrue();
});

it('survives the actionSave round-trip when hibpFailMode toggles from open to closed', function() {
    // Same shape as the previous test, but for hibpFailMode → pwnedFailMode.
    // Both aliases share the round-trip bug; both need coverage.
    $this->model->hibp = true;
    $this->model->hibpFailMode = 'open';

    $existing = $this->model->getAttributes();
    $submitted = ['hibpFailMode' => 'closed'];
    $merged = array_merge($existing, $submitted);

    $this->model->setAttributes($merged, false);

    expect($this->model->hibpFailMode)->toBe('closed');
});
