<?php
/**
 * Pest coverage for Feature 4 audit geolocation enrichment.
 *
 * Pins three contracts in `AuditLogService::logEvent()`:
 *
 *  - Geo populates ONLY on Enterprise + `geoIpEnabled` + a resolvable
 *    public IP. Lite/Pro, or the flag off, leaves `geoCountry` /
 *    `geoRegion` null even with a public IP in scope.
 *  - The raw IP is never stored — only the resolved country code lands
 *    in `geoCountry`.
 *  - **The hash chain still verifies with geo populated.** Geo columns
 *    are EXCLUDED from `canonicalize()`; a row with a populated
 *    `geoCountry` must still recompute to the same `rowHash` from the
 *    fixed canonical key set. This is the regression that guards
 *    `password-policy/audit/verify` against the geo addition.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Craft;
use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup — Enterprise + audit + geo on; swap in a web request with a public IP
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->settings->enableAuditLog;
    $this->originalGeoIpEnabled = $this->settings->geoIpEnabled;
    $this->originalRequest = Craft::$app->getRequest();

    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->enableAuditLog = true;
    $this->settings->geoIpEnabled = true;

    // A public IP DB-IP Lite resolves (Google DNS → US). The default
    // stub IP (203.0.113.7) is TEST-NET-3 reserved and would be
    // rejected as non-public by the provider's filter_var guard.
    $request = new WebRequestStub();
    $request->stubUserIp = '8.8.8.8';
    Craft::$app->set('request', $request);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    $this->plugin->edition = $this->originalEdition;
    $this->settings->enableAuditLog = $this->originalEnableAuditLog;
    $this->settings->geoIpEnabled = $this->originalGeoIpEnabled;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the most-recently inserted audit row.
 *
 * @return array<string, mixed>|null
 */
function latestGeoRow(): ?array
{
    /** @var array<string, mixed>|null $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->one();

    return $row;
}

// =============================================================================
// Enterprise + enabled — geo populates from the bundled database
// =============================================================================

it('populates geoCountry on Enterprise with geoIpEnabled and a public IP', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    $row = latestGeoRow();

    expect($row)->not->toBeNull();
    expect($row['geoCountry'])->toBeString();
    expect(strlen($row['geoCountry']))->toBe(2);
    // Never store the raw IP — geoCountry holds the country code only.
    expect($row['geoCountry'])->not->toBe('8.8.8.8');
})->skip(
    fn() => !is_file(
        dirname(__DIR__, 3) . '/src/data/geoip/dbip-country-lite.mmdb',
    ),
    'Bundled DB-IP Lite .mmdb is not present in this checkout.',
);

// =============================================================================
// Edition gate — Pro does not populate geo even with the flag on
// =============================================================================

it('leaves geo null on Pro edition even with geoIpEnabled on', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    $row = latestGeoRow();

    expect($row)->not->toBeNull();
    expect($row['geoCountry'])->toBeNull();
    expect($row['geoRegion'])->toBeNull();
});

// =============================================================================
// Feature flag — geoIpEnabled off leaves geo null even on Enterprise
// =============================================================================

it('leaves geo null when geoIpEnabled is off', function() {
    $this->settings->geoIpEnabled = false;

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    $row = latestGeoRow();

    expect($row)->not->toBeNull();
    expect($row['geoCountry'])->toBeNull();
    expect($row['geoRegion'])->toBeNull();
});

// =============================================================================
// Regression — the hash chain still verifies with geo populated
// =============================================================================

it('keeps the rowHash reproducible with geo populated (geo excluded from the chain)', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        outcome: 'success',
    );

    $row = latestGeoRow();

    expect($row)->not->toBeNull();
    // Confirm geo actually populated, otherwise this regression proves
    // nothing.
    expect($row['geoCountry'])->toBeString();

    // Recompute the canonical hash from the FIXED key set — note geo is
    // absent. The recomputed hash must match the stored rowHash; if geo
    // leaked into canonicalize(), this would diverge.
    $expectedPayload = AuditLogService::canonicalize([
        'changedByIdentifier' => $row['changedByIdentifier'],
        'dateCreated' => (new DateTime($row['dateCreated'], new DateTimeZone('UTC')))
            ->format(AuditLogService::CANONICAL_DATE_FORMAT),
        'details' => null,
        'event' => 'password_changed',
        'ipHash' => $row['ipHash'],
        'outcome' => 'success',
        'source' => $row['source'],
        'uid' => $row['uid'],
        'userIdentifier' => null,
    ]);

    $expectedHash = hash('sha256', $expectedPayload . $row['previousHash']);

    expect($row['rowHash'])->toBe($expectedHash);
})->skip(
    fn() => !is_file(
        dirname(__DIR__, 3) . '/src/data/geoip/dbip-country-lite.mmdb',
    ),
    'Bundled DB-IP Lite .mmdb is not present in this checkout.',
);
