<?php
/**
 * Pest coverage for `SettingsController::_stripEditionGatedKeys()` — the
 * shared edition-strip helper landed in the v5.2.0 pre-tag fix-pack.
 *
 * Both `actionSave()` and `actionApplyPreset()` build their settings
 * array on top of the full existing attribute set, so a stale higher-
 * edition key (e.g. left over from a downgrade) would be re-persisted
 * verbatim unless stripped on BOTH paths. The helper centralises that
 * strip. This file pins the tier mapping directly via reflection — no
 * project-config write, so the assertions stay deterministic under the
 * per-test transaction wrap:
 *
 *  - `alertCooldowns` and `enablePerGroupPolicies` are PRO keys per
 *    `docs/user/editions.md`. They survive on Pro and are stripped on Lite.
 *  - New-device alert keys (`enableNewDeviceAlerts`, `deviceRetentionDays`)
 *    are ENTERPRISE keys — the new-device alert EMAIL is an Enterprise
 *    feature. Device-row CAPTURE is universal (gate exposure, not capture),
 *    so the prune driven by `deviceRetentionDays` runs on every edition;
 *    the strip only stops a sub-Enterprise install persisting the toggle.
 *    Stripped on Lite + Pro, survive on Enterprise.
 *  - Audit-log CAPTURE keys (`enableAuditLog`, `auditLogRetentionDays`) are
 *    UNIVERSAL — capture runs on every edition, so they survive on Lite and
 *    Pro (project_audit_capture_principle.md: gate exposure, not capture).
 *  - SIEM / webhook / API / admin-alert keys are Enterprise EXPOSURE —
 *    stripped on Pro, survive on Enterprise.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\controllers\SettingsController;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;

    $this->controller = new SettingsController('settings', PasswordPolicy::$plugin);

    $this->method = (new ReflectionClass(SettingsController::class))
        ->getMethod('_stripEditionGatedKeys');
    $this->method->setAccessible(true);
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * A settings array carrying one representative key from every tier.
 */
function tieredSettings(): array
{
    return [
        // Lite (always survives)
        'minLength' => 12,
        // Pro
        'enablePerGroupPolicies' => true,
        'alertCooldowns' => ['breach' => 3600],
        // Universal capture (survives on every edition)
        'enableAuditLog' => true,
        'auditLogRetentionDays' => 365,
        // Enterprise exposure
        'enableNewDeviceAlerts' => true,
        'deviceRetentionDays' => 90,
        'geoIpEnabled' => true,
        'siemEnabled' => true,
        'webhooksEnabled' => true,
        'apiEnabled' => true,
    ];
}

// =============================================================================
// Lite — strips both Pro and Enterprise keys, keeps Lite keys
// =============================================================================

it('strips Pro and Enterprise keys on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $result = $this->method->invoke($this->controller, $this->plugin, tieredSettings());

    expect($result)->toHaveKey('minLength')
        ->and($result)->not->toHaveKey('enablePerGroupPolicies')
        ->and($result)->not->toHaveKey('enableNewDeviceAlerts')
        ->and($result)->not->toHaveKey('deviceRetentionDays')
        ->and($result)->not->toHaveKey('alertCooldowns')
        // Audit CAPTURE is universal — survives even on Lite.
        ->and($result)->toHaveKey('enableAuditLog')
        ->and($result)->toHaveKey('auditLogRetentionDays')
        ->and($result)->not->toHaveKey('geoIpEnabled')
        ->and($result)->not->toHaveKey('siemEnabled')
        ->and($result)->not->toHaveKey('webhooksEnabled')
        ->and($result)->not->toHaveKey('apiEnabled');
});

// =============================================================================
// Pro — keeps Pro keys, strips Enterprise keys (incl. new-device alerts)
// =============================================================================

it('keeps Pro keys but strips Enterprise keys (incl. new-device alerts) on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $result = $this->method->invoke($this->controller, $this->plugin, tieredSettings());

    // Pro keys survive.
    expect($result)->toHaveKey('enablePerGroupPolicies')
        ->and($result)->toHaveKey('alertCooldowns')
        // Audit CAPTURE is universal — survives on Pro too.
        ->and($result)->toHaveKey('enableAuditLog')
        ->and($result)->toHaveKey('auditLogRetentionDays')
        // Enterprise EXPOSURE keys stripped — new-device alerts are an
        // Enterprise feature.
        ->and($result)->not->toHaveKey('enableNewDeviceAlerts')
        ->and($result)->not->toHaveKey('deviceRetentionDays')
        ->and($result)->not->toHaveKey('geoIpEnabled')
        ->and($result)->not->toHaveKey('siemEnabled')
        ->and($result)->not->toHaveKey('webhooksEnabled')
        ->and($result)->not->toHaveKey('apiEnabled');
});

// =============================================================================
// Enterprise — every key survives
// =============================================================================

it('keeps every tier key on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    $result = $this->method->invoke($this->controller, $this->plugin, tieredSettings());

    expect($result)->toBe(tieredSettings());
});
