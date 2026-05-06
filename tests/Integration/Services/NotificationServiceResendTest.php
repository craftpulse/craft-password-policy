<?php
/**
 * Pest coverage for `NotificationService::resend()` — the admin-
 * triggered re-fire of a previously logged notification. The contract:
 *
 *  - Re-renders the template **fresh** from current state (admin may
 *    have edited the template since the original send) — does NOT
 *    replay the stored snapshot.
 *  - Writes a new row linked to the original via `resentFromId`.
 *  - Bypasses the dedup gate that normally suppresses a second send
 *    within the reminder window (admin click is an explicit override).
 *  - Returns false (without writing a row) when the row's
 *    `notificationType` isn't resendable — mailer-key paths
 *    (`new_device`, `admin_alert_*`) need the original event payload
 *    that we don't snapshot.
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
// Resend writes a new row chained to the original via resentFromId
// =============================================================================

it('writes a new sent row linked to the original via resentFromId', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // Original send — normal pipeline, success.
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord $original */
    $original = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    $dispatched = $this->plugin->getNotification()->resend($original);

    expect($dispatched)->toBeTrue();

    /** @var NotificationLogRecord $resent */
    $resent = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($resent->id)->not->toBe($original->id);
    expect($resent->resentFromId)->toBe($original->id);
    expect($resent->notificationType)->toBe('expiry_reminder');
    expect($resent->status)->toBe(NotificationStatus::Sent->value);
});

// =============================================================================
// Resend bypasses the dedup gate
// =============================================================================

it('resends even when the recent-success dedup window would normally block', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord $original */
    $original = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    // Sanity — a normal second call is suppressed by the dedup gate.
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);
    expect((int)NotificationLogRecord::find()->where(['userId' => $user->id])->count())->toBe(1);

    // Resend bypasses dedup explicitly.
    $this->plugin->getNotification()->resend($original);

    expect((int)NotificationLogRecord::find()->where(['userId' => $user->id])->count())->toBe(2);
});

// =============================================================================
// Resend re-renders fresh — picks up admin template edits
// =============================================================================

it('re-renders the template fresh and reflects post-edit changes', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord $original */
    $original = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    $originalSubject = $original->subject;

    // Admin edits the template.
    overwriteNotificationTemplateSubject('expiry-reminder', 'EDITED — {{ user.username }}');

    $this->plugin->getNotification()->resend($original);

    /** @var NotificationLogRecord $resent */
    $resent = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($resent->subject)->toContain('EDITED');
    expect($resent->subject)->not->toBe($originalSubject);
});

// =============================================================================
// Resend rejects mailer-key types (new_device, admin_alert_*)
// =============================================================================

it('returns false without writing a row when the type is not resendable', function() {
    $user = UserFactory::admin();

    // Seed a row whose type isn't resendable — `new_device` is a
    // mailer-key path, so the original event payload (deviceLabel,
    // maskedIp) isn't snapshotted in the log.
    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_notification_log}}', [
            'userId' => $user->id,
            'notificationType' => 'new_device',
            'status' => NotificationStatus::Sent->value,
            'recipientEmail' => 'recipient@example.test',
            'siteId' => null,
            'subject' => 'New device',
            'body' => 'Body',
            'errorMessage' => null,
            'resentFromId' => null,
            'sentAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
        ])
        ->execute();

    /** @var NotificationLogRecord $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->one();

    $rowsBefore = (int)NotificationLogRecord::find()->where(['userId' => $user->id])->count();

    $dispatched = $this->plugin->getNotification()->resend($row);

    expect($dispatched)->toBeFalse();

    $rowsAfter = (int)NotificationLogRecord::find()->where(['userId' => $user->id])->count();

    expect($rowsAfter)->toBe($rowsBefore);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Overwrites the subject field on the seeded notification template.
 * Used to verify the resend re-renders fresh — the new row's subject
 * should reflect this post-original edit.
 */
function overwriteNotificationTemplateSubject(string $key, string $newSubject): void
{
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $service = PasswordPolicy::$plugin->getNotificationTemplates();

    $template = $service->getTemplate($key, $primarySiteId);
    expect($template)->not->toBeNull();

    $template->subject = $newSubject;
    $service->saveTemplate($template);
}
