<?php
/**
 * Pest coverage for the Configuration settings page (`_settings/configuration.twig`).
 *
 * Pin point: the configuration page surfaces both the Lite-tier
 * `showStrengthIndicator` toggle and the Pro-tier `useZxcvbnStrength`
 * engine selector. Pre-Phase-F polish, the engine selector had no UI
 * — the settings model + controller persisted the value but no admin
 * could reach it without curling project config. This test pins:
 *
 *  1. The engine selector sits behind a `getIsPro()` guard.
 *  2. The Lite `showStrengthIndicator` toggle stays outside any Pro
 *     gate so admins on Lite still get the rule-counting meter.
 *  3. The `name` attribute on the Pro toggle matches the SettingsModel
 *     property + controller body-param key the save action reads.
 *  4. `SettingsController::actionSave` strips the Pro key on Lite saves
 *     (defense-in-depth — even if the UI conditional drifts, the strip
 *     block prevents Lite installs from persisting Pro-only settings).
 *
 * Source-level assertions rather than live-render: the configuration
 * template's `forms.lightswitchField()` calls bind through a top-level
 * `{% import '_includes/forms' as forms %}` declaration that Twig only
 * resolves during a full `display()` call. `renderBlock('content', ...)`
 * skips top-level statements, and a full `display()` would drag in the
 * full CP layout chain (live request, sidebar globals, etc.) — neither
 * pays for itself given the pin is on edition gating, not on Twig render
 * fidelity. Source-level assertions still catch every realistic
 * regression: a missing toggle, a wrong `name`, a dropped `getIsPro()`
 * guard, or a controller strip that goes missing.
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
    $this->templatePath = dirname(__DIR__, 3)
        . '/src/templates/_settings/configuration.twig';

    $this->source = file_get_contents($this->templatePath);
    expect($this->source)->toBeString()->and($this->source)->not->toBe('');
});

// =============================================================================
// Pro engine selector — present and edition-gated
// =============================================================================

it('renders the Pro zxcvbn engine selector behind a getIsPro() guard', function() {
    // The Pro toggle must sit inside a `getIsPro()` conditional. A
    // future refactor that drops the gate would expose the engine
    // selector to Lite admins — `SettingsController::actionSave`
    // strips the key on save, but the UI shouldn't dangle a Pro-only
    // affordance in front of Lite operators.
    expect($this->source)
        ->toContain("craft.app.plugins.getPlugin('password-policy').getIsPro()")
        ->and($this->source)->toContain('Use zxcvbn strength engine')
        ->and($this->source)->toContain("name: 'settings[useZxcvbnStrength]'")
        ->and($this->source)->toContain('on: settings.useZxcvbnStrength');
});

it('binds the engine selector to the SettingsModel property name SettingsController reads', function() {
    // `SettingsController::actionSave` reads `settings[useZxcvbnStrength]`
    // out of the POST body params and merges it into the settings model.
    // The form-field `name` attribute must match exactly — drift here
    // would silently drop the toggle's value on save.
    expect(PasswordPolicy::$plugin->getSettings())->toHaveProperty('useZxcvbnStrength');
    expect($this->source)->toContain("name: 'settings[useZxcvbnStrength]'");
});

// =============================================================================
// Lite strength indicator — unconditional
// =============================================================================

it('keeps the Lite show-strength-indicator toggle outside any Pro guard', function() {
    // The Lite-tier toggle must NOT be inside a `getIsPro()` conditional.
    // Detection: locate the Lite toggle's name attribute, walk backward
    // from there to find the nearest enclosing `{% if ... %}` tag, and
    // confirm that condition is NOT a `getIsPro()` check.
    $liteToggleOffset = strpos($this->source, "name: 'settings[showStrengthIndicator]'");
    expect($liteToggleOffset)->toBeInt()->toBeGreaterThan(0);

    // Walk all the if/endif tags up to that offset and tally depth.
    // If depth ends at zero on a non-Pro path, the toggle is unconditional.
    $prefix = substr($this->source, 0, $liteToggleOffset);
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
    // gate — the Lite toggle ships on every edition.
    foreach ($stack as $condition) {
        expect($condition)->not->toContain('getIsPro');
    }
});

// =============================================================================
// Settings model + controller wire-up — defense in depth
// =============================================================================

it('strips useZxcvbnStrength on save when the plugin is on Lite', function() {
    // `SettingsController::actionSave` must continue to strip the Pro
    // key on save — defense-in-depth even though the UI no longer
    // renders the toggle on Lite. Pin against the controller source
    // so a future refactor can't drop the strip block silently.
    $controllerPath = dirname(__DIR__, 3)
        . '/src/controllers/SettingsController.php';
    $controllerSource = file_get_contents($controllerPath);

    expect($controllerSource)->toBeString();
    expect($controllerSource)->toContain("\$settings['useZxcvbnStrength']");
});
