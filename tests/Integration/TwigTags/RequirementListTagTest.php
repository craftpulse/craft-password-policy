<?php
/**
 * Pest coverage for `RequirementListTag` — the front-end requirement-list
 * render builder.
 *
 * Pin points from the front-end a11y / scoping sweep:
 *  - `forField()` emits `data-pp-for="<id>"` on each `<li>` so the client JS
 *    scopes its pass/fail/pending repaint to one field's list instead of
 *    every list on the page.
 *  - Each `<li>` carries a visually-hidden `[data-pp-requirement-status]`
 *    span. The CSS `::before` glyph is decorative; the span is the
 *    programmatic met/not-met channel the client JS keeps in sync. It
 *    renders empty server-side so the no-JS baseline conveys no misleading
 *    state.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\twig\tags\RequirementListTag;

// =============================================================================
// Defaults
// =============================================================================

it('renders a <ul> with the data marker and at least one requirement item', function() {
    $html = (string)(new RequirementListTag());

    expect($html)->toStartWith('<ul')
        ->toContain('data-pp-requirements="1"')
        ->toContain('data-pp-requirement=')
        ->toEndWith('</ul>');
});

it('injects a visually-hidden status span per requirement item', function() {
    $html = (string)(new RequirementListTag());

    expect($html)->toContain('data-pp-requirement-status')
        ->toContain('pp-visually-hidden');
});

it('renders the status span empty so the no-JS baseline conveys no state', function() {
    $html = (string)(new RequirementListTag());

    // The span has no text content server-side — the JS fills it.
    expect($html)->toContain('data-pp-requirement-status></span>');
});

it('does not emit data-pp-for when no field association is set', function() {
    $html = (string)(new RequirementListTag());

    expect($html)->not->toContain('data-pp-for');
});

// =============================================================================
// forField() — per-field scoping association
// =============================================================================

it('emits data-pp-for on each li when associated with a field id via forField()', function() {
    $tag = new RequirementListTag();
    $result = $tag->forField('pp-password-abc123');

    expect($result)->toBe($tag);

    $html = (string)$tag;

    expect($html)->toContain('data-pp-for="pp-password-abc123"');
});

it('routes the forField key through the array constructor', function() {
    $html = (string)(new RequirementListTag(['forField' => 'pp-password-xyz']));

    expect($html)->toContain('data-pp-for="pp-password-xyz"');
});
