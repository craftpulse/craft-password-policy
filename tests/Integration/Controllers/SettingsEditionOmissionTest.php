<?php
/**
 * Pest coverage for the CP edition-gating rework (v5.2.0): lower editions must
 * NOT render higher-edition surfaces at all — no locked/badged upsell rows.
 *
 * These are source-level assertions on the settings templates rather than
 * live renders: the settings templates bind through a top-level
 * `{% import '_includes/forms' as forms %}` that Twig only resolves during a
 * full `display()` call, which would drag in the entire CP layout chain (live
 * request, sidebar globals). The realistic regression this guards against is a
 * higher-edition field drifting OUT of its `getIsPro()` / `getIsEnterprise()`
 * guard (re-exposing it on a lower edition) or a `badge` upsell marker
 * creeping back into the sidebar. Both are structural and catchable in source.
 *
 * The runtime whole-screen deny (Lite 403 on the Pro-only sections) is covered
 * separately in `SettingsSectionEditionGuardTest`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the raw source of a plugin template, relative to `src/templates/`.
 */
function ppTemplateSource(string $relativePath): string
{
    $path = dirname(__DIR__, 3) . '/src/templates/' . $relativePath;
    $source = file_get_contents($path);

    expect($source)->toBeString()->and($source)->not->toBe('');

    return $source;
}

/**
 * Walks every `{% if %}` / `{% endif %}` up to the first occurrence of
 * `$needle` in `$source` and returns the still-open enclosing conditions.
 *
 * @return string[] the raw condition expressions still on the stack at `$needle`
 */
function ppEnclosingConditions(string $source, string $needle): array
{
    $offset = strpos($source, $needle);
    expect($offset)->toBeInt()->toBeGreaterThan(0);

    $prefix = substr($source, 0, $offset);
    preg_match_all('/\{%-?\s*(if|endif)\b([^%]*)%\}/', $prefix, $matches, PREG_SET_ORDER);

    $stack = [];
    foreach ($matches as $match) {
        if ($match[1] === 'if') {
            $stack[] = $match[2];
            continue;
        }

        array_pop($stack);
    }

    return $stack;
}

/**
 * Asserts `$needle` sits inside at least one enclosing condition containing
 * `$guard` (e.g. `isPro`, `isEnterprise`) — i.e. it is omitted on editions
 * where the guard is false.
 */
function ppExpectGuarded(string $source, string $needle, string $guard): void
{
    $conditions = ppEnclosingConditions($source, $needle);
    $guarded = false;

    foreach ($conditions as $condition) {
        if (str_contains($condition, $guard)) {
            $guarded = true;
            break;
        }
    }

    expect($guarded)->toBeTrue("`{$needle}` should be omitted behind a `{$guard}` guard");
}

/**
 * Asserts `$needle` is NOT enclosed by any edition guard — it ships on every
 * edition.
 */
function ppExpectUniversal(string $source, string $needle): void
{
    foreach (ppEnclosingConditions($source, $needle) as $condition) {
        $isEditionGuard = str_contains($condition, 'isPro')
            || str_contains($condition, 'isEnterprise')
            || str_contains($condition, 'getIsPro')
            || str_contains($condition, 'getIsEnterprise');

        expect($isEditionGuard)->toBeFalse("`{$needle}` must not sit behind an edition guard: {$condition}");
    }
}

// =============================================================================
// Settings sidebar — Pro items omitted on Lite, no badge markup
// =============================================================================

it('omits the Pro-only settings sidebar items behind an isPro guard', function() {
    $source = ppTemplateSource('_layouts/password-policy-cp-settings.twig');

    ppExpectGuarded($source, "'groups': { title:", 'isPro');
    ppExpectGuarded($source, "'presets': { title:", 'isPro');
});

it('keeps Audit Logging in the sidebar on every edition (universal capture)', function() {
    $source = ppTemplateSource('_layouts/password-policy-cp-settings.twig');

    ppExpectUniversal($source, "'audit': { title:");
});

it('renders no edition badge markup in the settings sidebar', function() {
    $source = ppTemplateSource('_layouts/password-policy-cp-settings.twig');

    expect($source)->not->toContain('class="badge"');
    expect($source)->not->toContain('badge:');
});

// =============================================================================
// Mixed pages — higher-edition fields omitted, universal fields stay
// =============================================================================

it('omits HIBP-on-login on Lite but keeps the strength indicator universal', function() {
    $source = ppTemplateSource('_settings/configuration.twig');

    ppExpectGuarded($source, "name: 'settings[enableHibpOnLogin]'", 'isPro');
    ppExpectUniversal($source, "name: 'settings[showStrengthIndicator]'");
});

it('omits complexity mode on Lite but keeps the individual toggles universal', function() {
    $source = ppTemplateSource('_settings/rules.twig');

    ppExpectGuarded($source, "name: 'settings[complexityMode]'", 'isPro');
    ppExpectUniversal($source, "name: 'settings[numbers]'");
});

it('omits the minimum change interval on Lite', function() {
    $source = ppTemplateSource('_settings/history.twig');

    ppExpectGuarded($source, "name: 'settings[minChangeIntervalHours]'", 'isPro');
});

it('omits the advanced validators on Lite but keeps the common-password toggle universal', function() {
    $source = ppTemplateSource('_settings/validators.twig');

    ppExpectGuarded($source, "name: 'settings[checkSequentialChars]'", 'isPro');
    ppExpectGuarded($source, "name: 'settings[checkContextual]'", 'isPro');
    ppExpectUniversal($source, "name: 'settings[checkCommonPasswords]'");
});

it('omits Enterprise audit exposure fields but keeps audit capture universal', function() {
    $source = ppTemplateSource('_settings/audit.twig');

    ppExpectGuarded($source, "name: 'settings[adminAlertEmail]'", 'isEnterprise');
    ppExpectGuarded($source, "name: 'settings[geoIpEnabled]'", 'isEnterprise');
    ppExpectUniversal($source, "name: 'settings[enableAuditLog]'");
    ppExpectUniversal($source, "name: 'settings[auditLogRetentionDays]'");
});

// =============================================================================
// Notification template editor — Enterprise Twig-path field omitted, no badge
// =============================================================================

it('omits the Enterprise custom-Twig-template field below Enterprise with no badge', function() {
    $source = ppTemplateSource('_notifications/_edit.twig');

    ppExpectGuarded($source, "name: 'templatePath'", 'isEnterprise');
    expect($source)->not->toContain('class="badge"');
});
