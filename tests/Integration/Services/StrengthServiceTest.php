<?php
/**
 * Pest coverage for `StrengthService`. The service wraps `bjeavons/zxcvbn-php`
 * (a `require` Composer dep — always loaded) into the plugin's stable
 * `{engine, label, score, crackTime, suggestions, warning}` response shape.
 *
 * Pinned: the C2 commit c84aef3 blocklist-hit propagation. Without the
 * override, a blocklisted long+complex password reads as `excellent` while
 * the rule list correctly rejects it. The override clamps `label` + `score`
 * to weak/0 on blocklist hit but lets `crackTime`, `suggestions`, and
 * `warning` carry through unchanged so the user still sees zxcvbn's
 * dictionary breakdown.
 *
 * `compute()` is a thin pass-through to `analyzeZxcvbn()` — kept on the
 * service contract so a future engine swap doesn't have to renegotiate
 * call sites. Edition is irrelevant: the meter ships on every edition.
 *
 * @link      https://craft-pulse.com
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
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
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
// compute() — thin pass-through to analyzeZxcvbn on every edition
// =============================================================================

it('returns the zxcvbn shape on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $result = $this->service->compute('correct horse battery staple', $this->settings, [], false);

    expect($result['engine'])->toBe('zxcvbn')
        ->and($result)->toHaveKey('score')
        ->and($result)->toHaveKey('crackTime')
        ->and($result)->toHaveKey('suggestions')
        ->and($result)->toHaveKey('warning');
});

it('returns the zxcvbn shape on Lite (no edition gating on the meter)', function() {
    // The strength meter is Lite-or-better. The Pro upsell on strength
    // is the front-end Twig render-builder surface, not a different
    // algorithm — both editions hit the same engine.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $result = $this->service->compute('correct horse battery staple', $this->settings, [], false);

    expect($result['engine'])->toBe('zxcvbn')
        ->and($result)->toHaveKey('score');
});

it('preserves the blocklist override across the compute() pass-through', function() {
    // End-to-end: route through compute() with blocklistHit=true. The
    // pass-through shouldn't strip the flag.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

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
