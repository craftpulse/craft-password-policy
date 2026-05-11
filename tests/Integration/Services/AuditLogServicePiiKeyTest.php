<?php
/**
 * Pest coverage for `AuditLogService::_resolveAuditPiiKey()` — the
 * HMAC secret behind `userIdentifier` row writes. The privacy USP that
 * "rotating the audit-PII key destroys historical correlation without
 * breaking the rest of the site" depends on this resolver reading from
 * `SettingsModel::$auditPiiKey` first (operator-managed via
 * `CRAFT_AUDIT_PII_KEY`) and falling back to `securityKey` only when
 * the dedicated key is unset.
 *
 * Three contracts pinned here:
 *
 *  1. Fallback to `securityKey` when `auditPiiKey` is null/empty — keeps
 *     dev installs that skipped the generator hashable.
 *  2. Configured key overrides the fallback — set the property, the
 *     HMAC uses it.
 *  3. Different keys produce different hashes for the same email —
 *     the rotation lever actually severs correlation against the new
 *     key.
 *
 * Tests run on Pro edition (`enableAuditLog` flipped on at setup) and
 * use a real saved user via `UserFactory::admin()` so `_hashUserIdentifier()`
 * resolves an email.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup — Pro edition, audit log enabled, wipe rows so per-test queries are
// deterministic, snapshot the resolver-relevant settings to restore after
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->settings->enableAuditLog;
    $this->originalAuditPiiKey = $this->settings->auditPiiKey;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->enableAuditLog = true;
    $this->settings->auditPiiKey = null;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->enableAuditLog = $this->originalEnableAuditLog;
    $this->settings->auditPiiKey = $this->originalAuditPiiKey;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Fetches the userIdentifier column for the most-recently inserted row
 * for `$userId`. Tests inspect the column directly because the audit
 * service has no read API surface for the HMAC.
 */
function latestUserIdentifierFor(int $userId): ?string
{
    $value = (new Query())
        ->select(['userIdentifier'])
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['userId' => $userId])
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->scalar();

    return is_string($value) ? $value : null;
}

// =============================================================================
// Fallback to securityKey when CRAFT_AUDIT_PII_KEY is unset
// =============================================================================

it('hashes userIdentifier with securityKey when auditPiiKey is null', function() {
    $user = UserFactory::admin();
    $this->settings->auditPiiKey = null;

    $this->plugin->getAuditLog()->logEvent(
        userId: $user->id,
        event: 'password_changed',
    );

    $stored = latestUserIdentifierFor($user->id);
    $expected = hash_hmac(
        'sha256',
        $user->email,
        Craft::$app->getConfig()->getGeneral()->securityKey,
    );

    expect($stored)->toBe($expected);
});

// =============================================================================
// Uses configured auditPiiKey when set — the privacy lever wires up
// =============================================================================

it('hashes userIdentifier with the configured auditPiiKey when set', function() {
    $user = UserFactory::admin();
    $this->settings->auditPiiKey = 'test-pii-key-fixture';

    $this->plugin->getAuditLog()->logEvent(
        userId: $user->id,
        event: 'password_changed',
    );

    $stored = latestUserIdentifierFor($user->id);
    $expected = hash_hmac('sha256', $user->email, 'test-pii-key-fixture');

    expect($stored)->toBe($expected);
});

// =============================================================================
// Rotation property — different keys produce different hashes for same email
// =============================================================================

it('produces different userIdentifier hashes when auditPiiKey rotates', function() {
    $user = UserFactory::admin();

    $this->settings->auditPiiKey = 'key-before-rotation';
    $this->plugin->getAuditLog()->logEvent(
        userId: $user->id,
        event: 'password_changed',
    );
    $hashBefore = latestUserIdentifierFor($user->id);

    $this->settings->auditPiiKey = 'key-after-rotation';
    $this->plugin->getAuditLog()->logEvent(
        userId: $user->id,
        event: 'password_changed',
    );
    $hashAfter = latestUserIdentifierFor($user->id);

    expect($hashBefore)->not->toBeNull();
    expect($hashAfter)->not->toBeNull();
    expect($hashBefore)->not->toBe($hashAfter);
});
