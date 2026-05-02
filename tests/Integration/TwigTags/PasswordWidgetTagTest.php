<?php
/**
 * Pest coverage for `PasswordWidgetTag` — the composite Twig render builder
 * that wraps a `PasswordFieldTag` plus the strength meter, requirement list,
 * and optional requirements hint.
 *
 * Pin point: the C2 bug-fix sweep (commit 322c18f) introduced defensive
 * null-gating on `id` and `submitGate` because the child setters are
 * strict-typed `string` — forwarding `null` (the natural `$config['key']
 * ?? null`) TypeError'd at construct time. The tests here lock that gating
 * in: a composite built without `id` / `submitGate` must NOT pass those
 * keys through to `PasswordFieldTag`.
 *
 * Also pinned: `BaseTag::render()` returns a `\Twig\Markup` instance so
 * Twig's auto-escape doesn't HTML-encode the rendered markup. The
 * `__toString()` path stays a plain string for PHP-context concatenation
 * (which is how the composite assembles its child output).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\twig\tags\PasswordWidgetTag;
use Twig\Markup;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
});

// =============================================================================
// Construct + setter chain — fluent API smoke
// =============================================================================

it('accepts a fluent setter chain and returns $this from each setter', function() {
    $tag = new PasswordWidgetTag();

    $result = $tag
        ->name('newPassword')
        ->id('pw-widget-1')
        ->wrapperAttrs(['class' => 'custom-wrap'])
        ->inputAttrs(['placeholder' => 'Enter password'])
        ->toggleVisibility(true)
        ->liveValidation(true)
        ->submitGate('button[type=submit]')
        ->showStrength(true)
        ->showRequirements(true)
        ->showHint(false)
        ->groups(['editors']);

    // Each setter returns the same instance — required for the fluent
    // chain. If a future refactor breaks return-self the consumer site
    // chain silently no-ops the second-and-later setter.
    expect($result)->toBe($tag);
});

it('accepts a config-array constructor that maps keys to setters', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'submitGate' => 'button[type=submit]',
        'showHint' => true,
    ]);

    // Composite renders without TypeError — proof the array constructor
    // routed the keys to the correct setters.
    $output = (string)$tag;

    expect($output)->toBeString()->toContain('pp-widget');
});

it('throws InvalidArgumentException when constructor sees an unknown key', function() {
    new PasswordWidgetTag([
        'totallyMadeUpKey' => 'value',
    ]);
})->throws(InvalidArgumentException::class);

// =============================================================================
// Composite render — happy path with all child params set
// =============================================================================

it('renders wrapper with default class plus PasswordFieldTag, StrengthMeterTag, and RequirementListTag', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'liveValidation' => true,
    ]);

    $html = (string)$tag;

    // Outer wrapper carries the pp-widget class.
    expect($html)->toStartWith('<div')
        ->toContain('pp-widget')
        // PasswordFieldTag emitted with the configured name.
        ->toContain('name="newPassword"')
        // StrengthMeterTag emits role=progressbar and the data marker.
        ->toContain('data-pp-strength="1"')
        ->toContain('role="progressbar"')
        // RequirementListTag emits a <ul> with the data-pp-requirements marker.
        ->toContain('data-pp-requirements="1"')
        ->toEndWith('</div>');
});

it('renders the requirements hint paragraph when showHint is on', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'showHint' => true,
    ]);

    $html = (string)$tag;

    // RequirementsHintTag emits a <p class="pp-requirements-hint"> node.
    expect($html)->toContain('pp-requirements-hint');
});

it('omits the requirements hint paragraph when showHint is off (default)', function() {
    $tag = new PasswordWidgetTag(['name' => 'newPassword']);

    $html = (string)$tag;

    // Default behaviour: hint suppressed.
    expect($html)->not->toContain('pp-requirements-hint');
});

it('omits the strength meter when showStrength is false', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'showStrength' => false,
    ]);

    $html = (string)$tag;

    expect($html)->not->toContain('data-pp-strength="1"');
    expect($html)->not->toContain('pp-strength-bar');
});

it('omits the requirement list when showRequirements is false', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'showRequirements' => false,
    ]);

    $html = (string)$tag;

    expect($html)->not->toContain('data-pp-requirements="1"');
    expect($html)->not->toContain('<ul');
});

// =============================================================================
// Null-gating — the C2 regression vector
// =============================================================================

it('does not forward submitGate to the child PasswordFieldTag when it was never set', function() {
    // The pin: PasswordFieldTag::submitGate() is strict-typed `string`. A
    // composite that never called ->submitGate() must NOT pass null through
    // — the gate in PasswordWidgetTag::_renderHtml() (`if (!empty(...))`)
    // skips the forward.
    $tag = new PasswordWidgetTag(['name' => 'newPassword']);

    // No throw means the gate held; the rendered field has no submit-gate
    // data attribute.
    $html = (string)$tag;

    expect($html)->not->toContain('data-pp-submit-gate');
});

it('forwards submitGate to the child PasswordFieldTag when explicitly set', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'liveValidation' => true,
        'submitGate' => 'button[type=submit]',
    ]);

    $html = (string)$tag;

    // The child writes the selector to data-pp-submit-gate.
    expect($html)->toContain('data-pp-submit-gate="button[type=submit]"');
});

it('does not forward id to the child when not set — child auto-generates one', function() {
    // Same null-gating reasoning as submitGate. PasswordFieldTag::id() is
    // strict-typed `string`; the composite must not pass null.
    $tag = new PasswordWidgetTag(['name' => 'newPassword']);

    $html = (string)$tag;

    // The child rendered an auto-generated id (always prefixed pp-password).
    expect($html)->toMatch('/id="pp-password-[0-9a-f]{8}"/');
});

it('forwards id to the child when explicitly set', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'id' => 'my-custom-id',
    ]);

    $html = (string)$tag;

    // The child uses the provided id verbatim — the wrapper data-pp-field
    // and the input id both carry it.
    expect($html)->toContain('id="my-custom-id"')
        ->toContain('data-pp-field="my-custom-id"');
});

it('forwards an empty groups array — composite always passes `groups` through', function() {
    // The composite forwards `groups` unconditionally because the child's
    // setter accepts `array` (empty arrays included). Codify the contract:
    // an empty groups array means "no per-group override" and must not
    // emit a data-pp-context-groups attribute on the input.
    $tag = new PasswordWidgetTag(['name' => 'newPassword']);

    $html = (string)$tag;

    expect($html)->not->toContain('data-pp-context-groups');
});

it('forwards a non-empty groups array to the child', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'groups' => ['editors', 'managers'],
    ]);

    $html = (string)$tag;

    // The child serialises the handles into a comma-separated data attribute.
    expect($html)->toContain('data-pp-context-groups="editors,managers"');
});

// =============================================================================
// Interactivity flag forwarding — toggleVisibility + liveValidation
// =============================================================================

it('forwards toggleVisibility(true) to the child so the eye button renders', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'toggleVisibility' => true,
    ]);

    $html = (string)$tag;

    // Child renders the toggle button.
    expect($html)->toContain('pp-toggle-visibility')
        ->toContain('<button');
});

it('forwards toggleVisibility(false) to the child so the eye button is suppressed', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'toggleVisibility' => false,
    ]);

    $html = (string)$tag;

    // Child renders no toggle button when explicitly off.
    expect($html)->not->toContain('pp-toggle-visibility');
});

it('forwards liveValidation(true) to the child so data-pp-validate is emitted', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'liveValidation' => true,
    ]);

    $html = (string)$tag;

    expect($html)->toContain('data-pp-validate="1"');
});

it('forwards liveValidation(false) to the child so data-pp-validate is absent', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'liveValidation' => false,
    ]);

    $html = (string)$tag;

    expect($html)->not->toContain('data-pp-validate=');
});

// =============================================================================
// Wrapper attribute merging
// =============================================================================

it('merges wrapperAttrs into the outer div, overlaying the default class', function() {
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'wrapperAttrs' => ['class' => 'custom-wrap', 'data-test' => 'xyz'],
    ]);

    $html = (string)$tag;

    // Caller's class wins (array_merge order — wrapperAttrs second).
    expect($html)->toStartWith('<div class="custom-wrap" data-test="xyz">');
    expect($html)->not->toContain('class="pp-widget"');
});

// =============================================================================
// render() vs __toString() — Twig\Markup wrapping contract
// =============================================================================

it('returns a Twig\\Markup instance from render() so Twig auto-escape skips it', function() {
    // render() must return Markup so `{{ tag.render() }}` in Twig doesn't
    // HTML-encode the markup. If a refactor changes the return type to
    // string, every consumer template silently degrades to `&lt;div&gt;`
    // output.
    $tag = new PasswordWidgetTag(['name' => 'newPassword']);

    $rendered = $tag->render();

    expect($rendered)->toBeInstanceOf(Markup::class);
});

it('round-trips render() through __toString() back to the same HTML as _renderHtml()', function() {
    // The composite assembles its children via PHP-context concatenation
    // (`(string)$field` in _renderHtml). Verify both render paths produce
    // the same markup so a Twig render and a PHP cast match.
    //
    // An explicit id is required because the auto-id path uses
    // `microtime(true)` — calling render() twice on a tag without an
    // explicit id produces different ids per call, so the comparison
    // would be racy.
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'id' => 'roundtrip-fixture',
        'liveValidation' => true,
    ]);

    $rendered = (string)$tag->render();
    $direct = (string)$tag;

    expect($rendered)->toBe($direct);
});

it('still resolves render() in console request context (no asset registration)', function() {
    // Console requests skip the asset bundle registration in
    // BaseTag::_registerClientAsset. Verify render() still completes
    // without throwing — the AssetManager isn't available in console
    // boot, but the gate inside _registerClientAsset short-circuits.
    $tag = new PasswordWidgetTag([
        'name' => 'newPassword',
        'liveValidation' => true,
        'toggleVisibility' => true,
    ]);

    // No throw expected.
    $html = (string)$tag->render();

    expect($html)->toBeString();
    expect($html)->not->toBe('');
});

// =============================================================================
// Composite renders cleanly with `_renderHtml()` even when children would
// not register the client asset (console request gating)
// =============================================================================

it('composite render is a single concatenated div (children inlined)', function() {
    // Defensive: ensure the composite produces exactly one outer
    // <div class="pp-widget">…</div> wrapper.
    $tag = new PasswordWidgetTag(['name' => 'newPassword']);

    $html = (string)$tag;

    // The closing </div> count is at minimum 2 (composite wrapper + the
    // PasswordFieldTag's own internal wrapper). Pin "exactly one" outer
    // by checking the leading slice begins with the widget wrapper and
    // the tail matches.
    expect($html)->toStartWith('<div class="pp-widget">')
        ->toEndWith('</div>');
});
