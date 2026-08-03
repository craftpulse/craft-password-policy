<?php
/**
 * Pest coverage for the Configuration settings page (`_settings/configuration.twig`).
 *
 * Pin point: the configuration page surfaces the `showStrengthIndicator`
 * toggle that controls the CP strength meter. The meter ships on every
 * edition — there's a single zxcvbn-php strength engine across CP and
 * front-end Twig builders, so the toggle MUST stay outside any edition
 * gate. The Pro upsell on strength is the front-end render-builder
 * surface, not a different algorithm.
 *
 * Source-level assertions rather than live-render: the configuration
 * template's `forms.lightswitchField()` calls bind through a top-level
 * `{% import '_includes/forms' as forms %}` declaration that Twig only
 * resolves during a full `display()` call. `renderBlock('content', ...)`
 * skips top-level statements, and a full `display()` would drag in the
 * full CP layout chain (live request, sidebar globals, etc.) — neither
 * pays for itself given the pin is on edition gating, not on Twig render
 * fidelity. Source-level assertions still catch the realistic regression:
 * a Pro gate accidentally getting wrapped around the strength toggle.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->templatePath = dirname(__DIR__, 3)
        . '/src/templates/_settings/configuration.twig';

    $this->source = file_get_contents($this->templatePath);
    expect($this->source)->toBeString()->and($this->source)->not->toBe('');
});

// =============================================================================
// Strength indicator toggle — present on every edition
// =============================================================================

it('renders the show-strength-indicator toggle outside any Pro guard', function() {
    // The strength meter ships on every edition. The toggle must NOT be
    // inside a `getIsPro()` conditional. Detection: locate the toggle's
    // name attribute, walk all the if/endif tags up to that offset, and
    // verify no enclosing condition is a `getIsPro()` check.
    $toggleOffset = strpos($this->source, "name: 'settings[showStrengthIndicator]'");
    expect($toggleOffset)->toBeInt()->toBeGreaterThan(0);

    $prefix = substr($this->source, 0, $toggleOffset);
    preg_match_all('/\{%\s*(if|endif)\b([^%]*)%\}/', $prefix, $matches, PREG_SET_ORDER);

    $stack = [];
    foreach ($matches as $match) {
        if ($match[1] === 'if') {
            $stack[] = $match[2];
        } else {
            array_pop($stack);
        }
    }

    // Either no enclosing if at all, or the enclosing if isn't a Pro
    // gate — the toggle ships on every edition.
    foreach ($stack as $condition) {
        expect($condition)->not->toContain('getIsPro');
    }
});
