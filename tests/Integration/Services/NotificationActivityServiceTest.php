<?php
/**
 * Pest coverage for `NotificationActivityService` — the read-side
 * companion to `NotificationService`. Tests pin the query shapes
 * the CP activity index + per-user panel depend on: recent-for-user
 * ordering, filter combinations on the paginated read, distinct
 * type listing, and the recent-failure count.
 *
 * Direct DB inserts seed the notification log rows. The service is
 * pure read; no mailer interaction is in scope here. Capture-side
 * behavior (row writing on success / failure) is covered separately
 * in `NotificationServiceCaptureTest`.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use craftpulse\passwordpolicy\services\NotificationActivityService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getNotificationActivity();
});

// =============================================================================
// recentForUser — newest first, scoped, capped
// =============================================================================

it('returns rows for a single user newest first', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subDays(3));
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subDays(1));
    seedLogRow($user->id, 'breach_detected', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(2));

    $rows = $this->service->recentForUser($user->id);

    expect($rows)->toHaveCount(3);
    // Newest first
    expect($rows[0]->notificationType)->toBe('breach_detected');
    expect($rows[2]->notificationType)->toBe('expiry_reminder');
});

it('scopes recentForUser strictly to the requested userId', function() {
    $alice = UserFactory::admin();
    $bob = UserFactory::admin();

    seedLogRow($alice->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($bob->id, 'expiry_reminder', NotificationStatus::Sent);

    $rows = $this->service->recentForUser($alice->id);

    expect($rows)->toHaveCount(1);
    expect($rows[0]->userId)->toBe($alice->id);
});

it('caps recentForUser at the configured limit', function() {
    $user = UserFactory::admin();

    for ($i = 0; $i < 15; $i++) {
        seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subMinutes($i));
    }

    expect($this->service->recentForUser($user->id, 5))->toHaveCount(5);
    expect($this->service->recentForUser($user->id))->toHaveCount(NotificationActivityService::DEFAULT_PER_USER_LIMIT);
});

// =============================================================================
// paginated — filter shape + total count
// =============================================================================

it('paginates against the full table when no filters are passed', function() {
    $user = UserFactory::admin();

    for ($i = 0; $i < 5; $i++) {
        seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subHours($i));
    }

    $result = $this->service->paginated([], 1, 3);

    expect($result['total'])->toBe(5);
    expect($result['rows'])->toHaveCount(3);
});

it('filters paginated reads by status', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Failed);
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Failed);

    $result = $this->service->paginated(['status' => 'failed']);

    expect($result['total'])->toBe(2);
    foreach ($result['rows'] as $row) {
        expect($row->status)->toBe('failed');
    }
});

it('filters paginated reads by type', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($user->id, 'breach_detected', NotificationStatus::Sent);

    $result = $this->service->paginated(['notificationType' => 'breach_detected']);

    expect($result['total'])->toBe(1);
    expect($result['rows'][0]->notificationType)->toBe('breach_detected');
});

it('filters paginated reads by userId', function() {
    $alice = UserFactory::admin();
    $bob = UserFactory::admin();

    seedLogRow($alice->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($bob->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($bob->id, 'breach_detected', NotificationStatus::Sent);

    $result = $this->service->paginated(['userId' => $bob->id]);

    expect($result['total'])->toBe(2);
    foreach ($result['rows'] as $row) {
        expect($row->userId)->toBe($bob->id);
    }
});

it('rejects unknown status filter values rather than returning zero rows', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent);

    // Typo on the filter — service ignores unknown status string and
    // returns the full set, not an empty result that looks like a bug.
    $result = $this->service->paginated(['status' => 'gibberish']);

    expect($result['total'])->toBe(1);
});

// =============================================================================
// getById — null on miss, hydrated record on hit
// =============================================================================

it('returns null when getById misses', function() {
    expect($this->service->getById(999999))->toBeNull();
});

it('returns the hydrated record on getById hit', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent);
    /** @var NotificationLogRecord $row */
    $row = NotificationLogRecord::find()->where(['userId' => $user->id])->one();

    $found = $this->service->getById($row->id);

    expect($found)->not->toBeNull();
    expect($found->id)->toBe($row->id);
});

// =============================================================================
// knownTypes — distinct, sorted
// =============================================================================

it('returns distinct sorted notificationType values', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogRow($user->id, 'breach_detected', NotificationStatus::Sent);
    seedLogRow($user->id, 'admin_alert_breach', NotificationStatus::Sent);

    $types = $this->service->knownTypes();

    expect($types)->toEqual(['admin_alert_breach', 'breach_detected', 'expiry_reminder']);
});

// =============================================================================
// recentFailureCount — windowed scope
// =============================================================================

it('counts only failed rows within the requested hours-back window', function() {
    $user = UserFactory::admin();

    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(2));
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(20));
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(60));
    // Sent rows must NOT count even within the window
    seedLogRow($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subHours(1));

    expect($this->service->recentFailureCount(24))->toBe(2);
    expect($this->service->recentFailureCount(96))->toBe(3);
    expect($this->service->recentFailureCount(1))->toBe(0);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Direct insert into the notification log so tests can pin row-set
 * shape without going through the mailer.
 */
function seedLogRow(
    int $userId,
    string $type,
    NotificationStatus $status,
    ?Carbon $sentAt = null,
    ?string $recipientEmail = 'test@example.test',
    ?int $siteId = null,
    ?string $subject = 'Subject',
    ?string $body = 'Body',
    ?string $errorMessage = null,
    ?int $resentFromId = null,
): void {
    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_notification_log}}', [
            'userId' => $userId,
            'notificationType' => $type,
            'status' => $status->value,
            'recipientEmail' => $recipientEmail,
            'siteId' => $siteId,
            'subject' => $subject,
            'body' => $body,
            'errorMessage' => $errorMessage,
            'resentFromId' => $resentFromId,
            'sentAt' => ($sentAt ?? Carbon::now('UTC'))->format('Y-m-d H:i:s'),
        ])
        ->execute();
}
