<?php
/**
 * Pest coverage for `StrengthMeterTag` — the front-end strength-meter render
 * builder.
 *
 * Pin point: the front-end a11y / scoping sweep added `forField()`, which
 * emits `data-pp-for="<id>"` on the wrapper so the client JS can scope its
 * repaint to a single field's meter instead of every meter on the page. The
 * attribute must be present when associated and absent otherwise (a stray
 * empty `data-pp-for` would make the JS scope to the wrong nodes).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\twig\tags\StrengthMeterTag;

// =============================================================================
// Defaults
// =============================================================================

it('renders the progressbar wrapper with the data marker and aria role', function() {
    $html = (string)(new StrengthMeterTag());

    expect($html)->toContain('data-pp-strength="1"')
        ->toContain('role="progressbar"')
        ->toContain('aria-valuenow="0"')
        ->toContain('data-pp-strength-label');
});

it('does not emit data-pp-for when no field association is set', function() {
    $html = (string)(new StrengthMeterTag());

    expect($html)->not->toContain('data-pp-for');
});

// =============================================================================
// forField() — per-field scoping association
// =============================================================================

it('emits data-pp-for when associated with a field id via forField()', function() {
    $tag = new StrengthMeterTag();
    $result = $tag->forField('pp-password-abc123');

    // Fluent setter returns self.
    expect($result)->toBe($tag);

    $html = (string)$tag;

    expect($html)->toContain('data-pp-for="pp-password-abc123"');
});

it('routes the forField key through the array constructor', function() {
    $html = (string)(new StrengthMeterTag(['forField' => 'pp-password-xyz']));

    expect($html)->toContain('data-pp-for="pp-password-xyz"');
});
