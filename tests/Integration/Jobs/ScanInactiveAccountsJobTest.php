<?php
/**
 * Pest coverage for `ScanInactiveAccountsJob` — the Feature 5 (Pro) batched
 * inactive-account scan.
 *
 * Pins:
 *
 *  - report mode  — `processItem` is a no-op: no email row, no suspension.
 *  - notify mode  — a `notification_log` row of type `inactive_account` is
 *    written; the user is NOT suspended.
 *  - suspend mode — the user's native `suspended` flag flips; on Enterprise
 *    an `account_inactive` audit row is captured.
 *  - edition gate — `execute()` on a sub-Pro install short-circuits before
 *    touching any user (graceful skip, no throw).
 *
 * The batcher's detection query is exercised by `InactiveAccountServiceTest`;
 * here we drive `processItem` directly via reflection (the same pattern
 * `AuditExportJobTest` uses) so the action behaviour is pinned without
 * standing up a real queue runner.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\jobs\ScanInactiveAccountsJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

function runScanItem(string $action, $user): void
{
    $job = new ScanInactiveAccountsJob(['action' => $action]);
    $reflection = new ReflectionClass($job);
    $process = $reflection->getMethod('processItem');
    $process->invoke($job, $user);
}

// =============================================================================
// report mode — no-op
// =============================================================================

it('does not notify or suspend in report mode', function() {
    $user = UserFactory::admin();
    $user->email = 'scan-report@example.test';
    Craft::$app->getElements()->saveElement($user);

    runScanItem('report', $user);

    $reloaded = Craft::$app->getUsers()->getUserById((int)$user->id);
    expect($reloaded->suspended)->toBeFalse();

    $row = NotificationLogRecord::find()->where(['userId' => $user->id])->one();
    expect($row)->toBeNull();
});

// =============================================================================
// notify mode — email row, no suspension
// =============================================================================

it('writes an inactive_account notification row in notify mode', function() {
    $user = UserFactory::admin();
    $user->email = 'scan-notify@example.test';
    Craft::$app->getElements()->saveElement($user);

    runScanItem('notify', $user);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->notificationType)->toBe('inactive_account');

    $reloaded = Craft::$app->getUsers()->getUserById((int)$user->id);
    expect($reloaded->suspended)->toBeFalse();
});

// =============================================================================
// suspend mode — flips the native flag + Enterprise audit row
// =============================================================================

it('suspends the user and captures an audit row in suspend mode on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    $user = UserFactory::admin();

    runScanItem('suspend', $user);

    $reloaded = Craft::$app->getUsers()->getUserById((int)$user->id);
    expect($reloaded->suspended)->toBeTrue();

    $auditRow = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'account_inactive'])
        ->andWhere(['userId' => $user->id])
        ->one();

    expect($auditRow)->not->toBeNull();
});

// =============================================================================
// suspend mode — no audit row below Enterprise (capture gated to Enterprise)
// =============================================================================

it('does not capture an audit row in suspend mode on Pro', function() {
    $user = UserFactory::admin();

    runScanItem('suspend', $user);

    $reloaded = Craft::$app->getUsers()->getUserById((int)$user->id);
    expect($reloaded->suspended)->toBeTrue();

    $auditRow = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'account_inactive'])
        ->andWhere(['userId' => $user->id])
        ->one();

    expect($auditRow)->toBeNull();
});

// =============================================================================
// edition gate — execute() short-circuits below Pro
// =============================================================================

it('skips execution on a sub-Pro edition without throwing', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $job = new ScanInactiveAccountsJob(['action' => 'suspend']);

    // Must not throw — graceful skip per the queue edition-gate convention.
    $job->execute(Craft::$app->getQueue());

    expect(true)->toBeTrue();
});
