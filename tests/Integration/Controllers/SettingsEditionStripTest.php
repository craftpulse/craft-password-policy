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
 *  - New-device alert keys (`enableNewDeviceAlerts`, `deviceRetentionDays`)
 *    and `alertCooldowns` are PRO keys per `docs/user/editions.md` (the
 *    feature matrix lists new-device alerts as Pro+). They survive on
 *    Pro and are stripped on Lite.
 *  - Audit-log CAPTURE keys (`enableAuditLog`, `auditLogRetentionDays`) are
 *    UNIVERSAL — capture runs on every edition, so they survive on Lite and
 *    Pro (project_audit_capture_principle.md: gate exposure, not capture).
 *  - SIEM / webhook / API / admin-alert keys are Enterprise EXPOSURE —
 *    stripped on Pro, survive on Enterprise.
 *
 * @link      https://craftpulse.com
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
        'enableNewDeviceAlerts' => true,
        'deviceRetentionDays' => 90,
        'alertCooldowns' => ['breach' => 3600],
        // Universal capture (survives on every edition)
        'enableAuditLog' => true,
        'auditLogRetentionDays' => 365,
        // Enterprise exposure
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
        ->and($result)->not->toHaveKey('siemEnabled')
        ->and($result)->not->toHaveKey('webhooksEnabled')
        ->and($result)->not->toHaveKey('apiEnabled');
});

// =============================================================================
// Pro — keeps Pro keys (incl. new-device alerts), strips Enterprise keys
// =============================================================================

it('keeps Pro new-device-alert keys but strips Enterprise keys on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $result = $this->method->invoke($this->controller, $this->plugin, tieredSettings());

    // Pro keys survive — new-device alerts are a documented Pro feature.
    expect($result)->toHaveKey('enablePerGroupPolicies')
        ->and($result)->toHaveKey('enableNewDeviceAlerts')
        ->and($result)->toHaveKey('deviceRetentionDays')
        ->and($result)->toHaveKey('alertCooldowns')
        // Audit CAPTURE is universal — survives on Pro too.
        ->and($result)->toHaveKey('enableAuditLog')
        ->and($result)->toHaveKey('auditLogRetentionDays')
        // Enterprise EXPOSURE keys stripped.
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
