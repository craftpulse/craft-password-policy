<?php
/**
 * Pest coverage for `AuditLogService::EVENT_AUDIT_CHAIN_ROTATED` — the
 * Phase G observability seam fired when the retention prune deletes one
 * or more rows.
 *
 * Contract:
 *
 *  - Fires once per successful prune that deleted >= 1 row AND left
 *    >= 1 row standing.
 *  - Payload: `(startId, startRowHash, endId, endRowHash, rotatedAt)`.
 *    Consumers use the start pair to anchor the verifier's next walk
 *    and the end pair to record the rotation boundary externally.
 *  - Skipped when the prune deleted zero rows OR emptied the table.
 *
 * Tests bypass the playground's audit-log feature flag by toggling
 * `enableAuditLog` and seed rows directly via the chain-aware
 * `logEvent()` so the rotation event sees real chain data, not test
 * placeholders.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craftpulse\passwordpolicy\events\AuditChainRotatedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use yii\base\Event;

// =============================================================================
// Setup — flip enableAuditLog on, wipe pre-existing rows
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
    Event::off(AuditLogService::class, AuditLogService::EVENT_AUDIT_CHAIN_ROTATED);
});

// =============================================================================
// Helper — back-date a row's `dateCreated` so the prune deletes it
// =============================================================================

function backdateAuditRow(int $id, string $dateCreated): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            ['dateCreated' => $dateCreated],
            ['id' => $id],
        )
        ->execute();
}

// =============================================================================
// Fires with correct payload after a successful prune
// =============================================================================

it('fires AuditChainRotatedEvent when the prune deletes rows but leaves a head', function() {
    $service = $this->plugin->getAuditLog();

    // Seed three chained rows. We'll back-date the first two to make the
    // prune drop them, leaving row 3 as the new chain head.
    $service->logEvent(userId: null, event: 'old_one');
    $service->logEvent(userId: null, event: 'old_two');
    $service->logEvent(userId: null, event: 'recent_three');

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    expect($rows)->toHaveCount(3);

    $oldThreshold = Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s');
    backdateAuditRow((int)$rows[0]['id'], $oldThreshold);
    backdateAuditRow((int)$rows[1]['id'], $oldThreshold);

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 5);

    expect($deleted)->toBe(2);
    expect($captured)->toBeInstanceOf(AuditChainRotatedEvent::class);
    expect($captured->endId)->toBe((int)$rows[1]['id']);
    expect($captured->endRowHash)->toBe($rows[1]['rowHash']);
    expect($captured->startId)->toBe((int)$rows[2]['id']);
    expect($captured->startRowHash)->toBe($rows[2]['rowHash']);
    expect($captured->rotatedAt)->toBeInstanceOf(\DateTime::class);
});

// =============================================================================
// Skips the event when the prune deleted zero rows
// =============================================================================

it('does not fire when the prune deletes zero rows', function() {
    $service = $this->plugin->getAuditLog();

    $service->logEvent(userId: null, event: 'recent_only');

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 365);

    expect($deleted)->toBe(0);
    expect($captured)->toBeNull();
});

// =============================================================================
// Skips the event when the prune emptied the table (no surviving head)
// =============================================================================

it('does not fire when the prune emptied the table', function() {
    $service = $this->plugin->getAuditLog();

    $service->logEvent(userId: null, event: 'old_only_one');
    $service->logEvent(userId: null, event: 'old_only_two');

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    $oldThreshold = Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s');
    foreach ($rows as $row) {
        backdateAuditRow((int)$row['id'], $oldThreshold);
    }

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 5);

    expect($deleted)->toBe(2);
    expect($captured)->toBeNull();
});
