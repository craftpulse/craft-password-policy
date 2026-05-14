<?php
/**
 * Pest coverage for `ComplianceAggregateService` — the G3 read-only
 * aggregate surface that powers the compliance dashboard + reports.
 *
 * Pinned contracts:
 *
 *  - `getTotals()` returns total + last-30-day + by-event counts that
 *    match the fixture rows.
 *  - `getChainHealth()` returns `healthy` on a clean chain; flips to
 *    `broken` with a populated `firstBreakRowId` once a row's stored
 *    hash is tampered with.
 *  - `getAlertCooldownActivity()` returns per-event-class fire counts
 *    grouped from the cooldowns table.
 *  - `getPendingForwards()` returns the unforwarded count + the oldest
 *    pending row's human-duration age.
 *  - `getRetentionStatus()` returns the configured retention windows
 *    plus oldest-row age for both retention-managed logs.
 *
 * Cache invalidation is NOT tested — the 5-minute TTL is intentional
 * UX-perceptible staleness for a CP dashboard that may render on every
 * page load. Each test flushes the cache in setup so the assertions
 * see fresh aggregates; we never verify the cache-hit path because the
 * dashboard's contract is "data freshish-within-5-minutes", not
 * "every render hits the DB".
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use craftpulse\passwordpolicy\services\ComplianceAggregateService;

// =============================================================================
// Setup — wipe rows + cache, enable audit logging so writer-side seed works
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getComplianceAggregates();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    // Aggregate service runs on every edition — pinning Pro here so the
    // fixture seeds (UserFactory etc.) succeed; the service itself
    // doesn't read the edition flag.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_alert_cooldowns}}')
        ->execute();

    Craft::$app->getCache()->flush();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts an audit-log row directly via SQL (bypasses chain writer for
 * fixture speed). Pairs with `craft_elements` per Step 5 element-ification.
 *
 * @param array<string, mixed> $overrides
 * @return int the new row's id
 */
function seedComplianceAuditRow(array $overrides = []): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert(Table::ELEMENTS, [
            'type' => AuditLogElement::class,
            'enabled' => 1,
            'archived' => 0,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    $elementId = (int)Craft::$app->getDb()->getLastInsertID(Table::ELEMENTS);

    $row = array_merge([
        'id' => $elementId,
        'event' => 'password_changed',
        'outcome' => 'success',
        'source' => 'admin',
        'rowHash' => str_repeat('a', 64),
        'previousHash' => str_repeat('0', 64),
        'forwardedAt' => null,
        'forwardAttempts' => 0,
        'dateCreated' => $now,
        'uid' => StringHelper::UUID(),
    ], $overrides);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', $row)
        ->execute();

    return $elementId;
}

/**
 * Inserts an alert-cooldown row directly via SQL.
 */
function seedComplianceCooldownRow(string $eventClass, string $cooldownKey, ?string $firedAt = null): void
{
    $now = $firedAt ?? Carbon::now('UTC')->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_alert_cooldowns}}', [
            'eventClass' => $eventClass,
            'cooldownKey' => $cooldownKey,
            'firedAt' => $now,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();
}

// =============================================================================
// getTotals
// =============================================================================

it('returns total + last30Days + by-event-class counts', function() {
    seedComplianceAuditRow(['event' => 'password_changed']);
    seedComplianceAuditRow(['event' => 'password_changed']);
    seedComplianceAuditRow(['event' => 'account_locked']);

    $totals = $this->service->getTotals();

    expect($totals['total'])->toBe(3);
    expect($totals['last30Days'])->toBe(3);
    expect($totals['byEventClass'])->toBe([
        'account_locked' => 1,
        'password_changed' => 2,
    ]);
});

it('returns zeros when the audit log is empty', function() {
    $totals = $this->service->getTotals();

    expect($totals['total'])->toBe(0);
    expect($totals['last30Days'])->toBe(0);
    expect($totals['byEventClass'])->toBe([]);
});

it('excludes rows older than 30 days from last30Days but includes them in total', function() {
    $oldDate = Carbon::now('UTC')->subDays(45)->format('Y-m-d H:i:s');

    seedComplianceAuditRow(['event' => 'password_changed', 'dateCreated' => $oldDate]);
    seedComplianceAuditRow(['event' => 'password_changed']);

    $totals = $this->service->getTotals();

    expect($totals['total'])->toBe(2);
    expect($totals['last30Days'])->toBe(1);
});

// =============================================================================
// getChainHealth
// =============================================================================

it('returns healthy against an empty chain', function() {
    $health = $this->service->getChainHealth();

    expect($health['status'])->toBe('healthy');
    expect($health['firstBreakRowId'])->toBeNull();
    expect($health['checkedRowCount'])->toBe(0);
    expect($health['lastRunAt'])->toBeInstanceOf(\DateTime::class);
});

it('returns healthy against a chain seeded via the real writer', function() {
    // The writer produces bit-identical canonical bytes the verifier
    // walks — seeding via `logEvent` is the closest thing to production.
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    $health = $this->service->getChainHealth();

    expect($health['status'])->toBe('healthy');
    expect($health['firstBreakRowId'])->toBeNull();
    expect($health['checkedRowCount'])->toBe(2);
});

it('returns broken with firstBreakRowId set when a row is tampered', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    // Tamper with the second row's stored rowHash.
    $secondRow = (new Query())
        ->select(['id'])
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->offset(1)
        ->limit(1)
        ->one();

    expect($secondRow)->toBeArray();

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            ['rowHash' => str_repeat('b', 64)],
            ['id' => (int)$secondRow['id']],
        )
        ->execute();

    // Bust the chain-health cache so the verifier walks again after
    // the tamper.
    Craft::$app->getCache()->delete(
        ComplianceAggregateService::CACHE_KEY_CHAIN_HEALTH,
    );

    $health = $this->service->getChainHealth();

    expect($health['status'])->toBe('broken');
    expect($health['firstBreakRowId'])->toBe((int)$secondRow['id']);
});

// =============================================================================
// getAlertCooldownActivity
// =============================================================================

it('returns per-event-class fire counts grouped from the last 24 hours', function() {
    seedComplianceCooldownRow('admin_security_alert:account_locked', 'k1');
    seedComplianceCooldownRow('admin_security_alert:account_locked', 'k2');
    seedComplianceCooldownRow('admin_security_alert:breach_detected', 'k3');

    $activity = $this->service->getAlertCooldownActivity();

    expect($activity['last24h'])->toBe(3);
    expect($activity['byEventClass'])->toBe([
        'admin_security_alert:account_locked' => 2,
        'admin_security_alert:breach_detected' => 1,
    ]);
});

it('excludes cooldown rows fired more than 24 hours ago', function() {
    $oldFired = Carbon::now('UTC')->subDays(2)->format('Y-m-d H:i:s');

    seedComplianceCooldownRow('admin_security_alert:account_locked', 'k1', $oldFired);
    seedComplianceCooldownRow('admin_security_alert:account_locked', 'k2');

    $activity = $this->service->getAlertCooldownActivity();

    expect($activity['last24h'])->toBe(1);
    expect($activity['byEventClass'])->toBe([
        'admin_security_alert:account_locked' => 1,
    ]);
});

// =============================================================================
// getPendingForwards
// =============================================================================

it('returns count=N + oldestAge string when N rows have forwardedAt IS NULL', function() {
    seedComplianceAuditRow(['forwardedAt' => null]);
    seedComplianceAuditRow(['forwardedAt' => null]);

    $pending = $this->service->getPendingForwards();

    expect($pending['count'])->toBe(2);
    expect($pending['oldestAge'])->toBeString();
});

it('returns count=0 + oldestAge=null when all rows are forwarded', function() {
    $forwardedAt = Carbon::now('UTC')->format('Y-m-d H:i:s');

    seedComplianceAuditRow(['forwardedAt' => $forwardedAt]);

    $pending = $this->service->getPendingForwards();

    expect($pending['count'])->toBe(0);
    expect($pending['oldestAge'])->toBeNull();
});

// =============================================================================
// getRetentionStatus
// =============================================================================

it('returns configured retention windows + oldest row age', function() {
    seedComplianceAuditRow();

    $retention = $this->service->getRetentionStatus();

    expect($retention['auditLogRetentionDays'])->toBe(
        $this->plugin->getSettings()->auditLogRetentionDays,
    );
    expect($retention['notificationLogRetentionDays'])->toBe(
        $this->plugin->getSettings()->notificationLogRetentionDays,
    );
    expect($retention['auditLogOldestAge'])->toBeString();
    expect($retention['auditLogProjectedNextPrune'])->toBeInstanceOf(\DateTime::class);
});

it('returns null oldest-age values when both retention tables are empty', function() {
    // Notification log might have rows from prior tests but the
    // transaction wrap should isolate. The audit-log wipe is in
    // beforeEach; ensure notification log too for isolation.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_notification_log}}')
        ->execute();

    $retention = $this->service->getRetentionStatus();

    expect($retention['auditLogOldestAge'])->toBeNull();
    expect($retention['auditLogProjectedNextPrune'])->toBeNull();
    expect($retention['notificationLogOldestAge'])->toBeNull();
});

// =============================================================================
// Use the public canonical-date constant (defensive — pin the contract)
// =============================================================================

it('uses the same canonical date format as the writer for chain verification', function() {
    // Lock the contract: ComplianceAggregateService relies on
    // AuditLogService::CANONICAL_DATE_FORMAT staying intact. A test
    // here means a drift between the writer's constant and the
    // verifier's hardcoded value breaks at test time, not in
    // production.
    expect(AuditLogService::CANONICAL_DATE_FORMAT)->toBe('Y-m-d\TH:i:s\Z');
});
