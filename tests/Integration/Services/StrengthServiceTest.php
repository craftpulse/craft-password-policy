<?php
/**
 * Pest coverage for `StrengthService` — both engines (rule-counting
 * baseline and zxcvbn-php) plus the `compute()` router. Pins the
 * blocklist-hit propagation that landed in C2 commit c84aef3:
 * Engine B previously returned zxcvbn's score/label as-is, so a
 * blocklisted long+complex password read as `excellent` while the
 * rule list correctly rejected it. The fix routes blocklist hits to
 * override Engine B's output to `weak` + score 0.
 *
 * The override is intentionally narrow — only `label` + `score` get
 * clamped. `crackTime`, `suggestions`, and `warning` survive zxcvbn's
 * analysis unchanged. Pinned here so a refactor that "fixes" the
 * narrow scope (clearing all fields on blocklist hit) doesn't silently
 * regress the user-visible suggestions list.
 *
 * `compute()` routing tests cover the gate that picks Engine B —
 * Pro edition AND `useZxcvbnStrength=true` AND zxcvbn-php loaded.
 * Engine A path verified for the Lite / opt-out fallback.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getStrength();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalUseZxcvbn = $this->settings->useZxcvbnStrength;

    // Strength tests run against Pro by default — Engine B requires Pro
    // AND `useZxcvbnStrength=true`. Individual tests downshift to Lite or
    // toggle the setting to exercise the fallback branches.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->useZxcvbnStrength = true;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->useZxcvbnStrength = $this->originalUseZxcvbn;
});

// =============================================================================
// analyzeZxcvbn — happy path (no blocklist hit)
// =============================================================================

it('returns zxcvbn score + label as-is when no blocklist hit', function() {
    // A reasonably strong novel password — zxcvbn should return a score
    // ≥3 with no suggestions. Don't pin the exact score (zxcvbn can shift
    // its scoring across minor versions); pin the SHAPE: engine identifier,
    // label vocabulary maps to one of the four known values, score in
    // the 0-4 range, suggestions/crackTime/warning fields present.
    $result = $this->service->analyzeZxcvbn(
        'tHis-Is-A-Pretty-S0lid-Passphrase-2026',
        $this->settings,
        [],
        false,
    );

    expect($result['engine'])->toBe('zxcvbn')
        ->and($result['label'])->toBeIn(['weak', 'fair', 'strong', 'excellent'])
        ->and($result['score'])->toBeInt()
        ->and($result['score'])->toBeGreaterThanOrEqual(0)
        ->and($result['score'])->toBeLessThanOrEqual(4)
        ->and($result['crackTime'])->toBeString()
        ->and($result['suggestions'])->toBeArray()
        ->and($result['warning'])->toBeString();
});

it('returns label "weak" + score 0 for the empty string', function() {
    // zxcvbn's score floor is 0; the engine's score-to-label match maps
    // 0 and 1 both to 'weak'. Pin the floor explicitly — it's the
    // zxcvbn-side baseline that the blocklist override has to match.
    $result = $this->service->analyzeZxcvbn('', $this->settings, [], false);

    expect($result['engine'])->toBe('zxcvbn')
        ->and($result['label'])->toBe('weak')
        ->and($result['score'])->toBe(0);
});

// =============================================================================
// analyzeZxcvbn — blocklist hit override (the C2 bug-fix regression vector)
// =============================================================================

it('forces label "weak" and score 0 when blocklist hit is true', function() {
    // The exact test the C2 fix shipped to address: a long+complex
    // password that zxcvbn would otherwise rate as strong, with the
    // blocklistHit flag forced on. Override must clamp both fields.
    $result = $this->service->analyzeZxcvbn(
        'tHis-Is-A-Pretty-S0lid-Passphrase-2026',
        $this->settings,
        [],
        true, // blocklistHit
    );

    expect($result['engine'])->toBe('zxcvbn')
        ->and($result['label'])->toBe('weak')
        ->and($result['score'])->toBe(0);
});

it('preserves crackTime, suggestions, and warning when blocklist hit overrides label', function() {
    // The override is narrow by design — only `label` + `score` get
    // clamped. Suggestions / crackTime / warning carry through from
    // zxcvbn so the user still sees the dictionary breakdown. Pinned
    // here so a refactor that "cleans up" by clearing every field on
    // blocklist hit silently regresses the user-visible feedback.
    $result = $this->service->analyzeZxcvbn(
        'tHis-Is-A-Pretty-S0lid-Passphrase-2026',
        $this->settings,
        [],
        true,
    );

    expect($result)->toHaveKey('crackTime')
        ->and($result)->toHaveKey('suggestions')
        ->and($result)->toHaveKey('warning')
        ->and($result['crackTime'])->toBeString()
        ->and($result['suggestions'])->toBeArray()
        ->and($result['warning'])->toBeString();
});

it('honours blocklist hit even when zxcvbn would otherwise rate the password high', function() {
    // Two scenarios in one assertion: hits=true forces weak, hits=false
    // returns the natural reading. Lets the diff show the override
    // moved the meter down rather than coincidentally finding a low
    // password.
    $password = 'tHis-Is-A-Pretty-S0lid-Passphrase-2026';

    $natural = $this->service->analyzeZxcvbn($password, $this->settings, [], false);
    $override = $this->service->analyzeZxcvbn($password, $this->settings, [], true);

    expect($override['label'])->toBe('weak')
        ->and($override['score'])->toBe(0)
        ->and($natural['score'])->toBeGreaterThan($override['score']);
});

// =============================================================================
// analyzeZxcvbn — context (username/email) feeds zxcvbn's user-input dictionary
// =============================================================================

it('uses context as user-input dictionary so a name-based password scores low', function() {
    // zxcvbn's user-input dictionary penalises passwords that match
    // strings the user knows about (their own username / email). Pin
    // the contract: a context with username 'jbloggs' + email
    // 'jbloggs@example.com' should weaken a password derived from
    // those tokens.
    $contextual = $this->service->analyzeZxcvbn(
        'JbloggsJbloggs1!',
        $this->settings,
        ['username' => 'jbloggs', 'email' => 'jbloggs@example.com'],
        false,
    );

    $noContext = $this->service->analyzeZxcvbn(
        'JbloggsJbloggs1!',
        $this->settings,
        [],
        false,
    );

    // With the context, zxcvbn's dictionary should match — the score
    // is no higher than the no-context reading.
    expect($contextual['score'])->toBeLessThanOrEqual($noContext['score']);
});

// =============================================================================
// analyzeBaseline — blocklist hit override (Engine A side, regression guard)
// =============================================================================

it('forces baseline label to "weak" on blocklist hit regardless of length', function() {
    // Long, complex, high-tier password — Engine A would normally call
    // this 'strong' or 'excellent'. blocklistHit override clamps to weak.
    $result = $this->service->analyzeBaseline(
        'aB1!aB1!aB1!aB1!aB1!',
        $this->settings,
        true,
    );

    expect($result['engine'])->toBe('baseline')
        ->and($result['label'])->toBe('weak');
});

it('returns the natural baseline label when no blocklist hit', function() {
    // Same password, blocklistHit=false — verify the override is
    // actually doing work above (i.e. the natural reading is high).
    $result = $this->service->analyzeBaseline(
        'aB1!aB1!aB1!aB1!aB1!',
        $this->settings,
        false,
    );

    expect($result['engine'])->toBe('baseline')
        ->and($result['label'])->toBeIn(['strong', 'excellent']);
});

// =============================================================================
// compute() — routing between engines
// =============================================================================

it('routes through Engine B when Pro edition + useZxcvbnStrength is on', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->useZxcvbnStrength = true;

    $result = $this->service->compute('correct horse battery staple', $this->settings, [], false);

    expect($result['engine'])->toBe('zxcvbn');
});

it('falls back to Engine A on Lite edition even when useZxcvbnStrength is on', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->useZxcvbnStrength = true;

    $result = $this->service->compute('correct horse battery staple', $this->settings, [], false);

    expect($result['engine'])->toBe('baseline');
});

it('falls back to Engine A when useZxcvbnStrength is off', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->useZxcvbnStrength = false;

    $result = $this->service->compute('correct horse battery staple', $this->settings, [], false);

    expect($result['engine'])->toBe('baseline');
});

it('preserves the blocklist override across the compute() router (Engine B)', function() {
    // End-to-end: route through compute() on Engine B with
    // blocklistHit=true. The route shouldn't strip the flag.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->useZxcvbnStrength = true;

    $result = $this->service->compute(
        'tHis-Is-A-Pretty-S0lid-Passphrase-2026',
        $this->settings,
        [],
        true,
    );

    expect($result['engine'])->toBe('zxcvbn')
        ->and($result['label'])->toBe('weak')
        ->and($result['score'])->toBe(0);
});

it('preserves the blocklist override across the compute() router (Engine A)', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->useZxcvbnStrength = false;

    $result = $this->service->compute(
        'aB1!aB1!aB1!aB1!aB1!',
        $this->settings,
        [],
        true,
    );

    expect($result['engine'])->toBe('baseline')
        ->and($result['label'])->toBe('weak');
});
