<?php
/**
 * Pest coverage for `NotificationService`'s capture invariant — every
 * send attempt writes a row in `passwordpolicy_notification_log`,
 * regardless of outcome. The pre-Phase-F2 behavior (row only on
 * success, failures only logged to the plugin log file) was a side-
 * effect dedup substrate that pretended to be an audit table; this
 * file pins the new contract so a future regression that drops the
 * failure-path write fails loudly.
 *
 * Failure scenarios are induced by overwriting the seeded notification
 * template's body to invalid Twig. `composeFromTemplate()` calls
 * `View::renderString()` on the body, which throws on broken syntax,
 * which propagates into the dispatch path's catch block, which writes
 * `status = 'failed'` with the Twig exception message captured.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

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
// Success path — row written with status=sent + rendered subject + body
// =============================================================================

it('writes a sent row when send() succeeds', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Sent->value);
    expect($row->notificationType)->toBe('expiry_reminder');
    expect($row->recipientEmail)->toBe('recipient@example.test');
    expect($row->errorMessage)->toBeNull();
    // Subject + body should be populated with rendered Twig output —
    // the seeded `expiry-reminder` template includes `{{ user }}` and
    // `{{ daysUntilExpiry }}` token references that resolve at send.
    expect($row->subject)->not->toBeNull();
    expect($row->body)->not->toBeNull();
});

// =============================================================================
// Failure path — row written with status=failed + errorMessage
// =============================================================================

it('writes a failed row with errorMessage when template rendering throws', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    breakNotificationTemplate('expiry-reminder');

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Failed->value);
    expect($row->notificationType)->toBe('expiry_reminder');
    expect($row->recipientEmail)->toBe('recipient@example.test');
    expect($row->errorMessage)->not->toBeNull();
    expect($row->errorMessage)->not->toBe('');
});

// =============================================================================
// Dedup decoupled from row existence — failed-then-retried not suppressed
// =============================================================================

it('does not suppress a retry after a failed attempt', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // First attempt fails — broken template throws on render.
    breakNotificationTemplate('expiry-reminder');
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    // Restore the template so the retry can succeed.
    restoreNotificationTemplate('expiry-reminder');
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord[] $rows */
    $rows = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'expiry_reminder'])
        ->orderBy(['id' => SORT_ASC])
        ->all();

    expect($rows)->toHaveCount(2);
    expect($rows[0]->status)->toBe(NotificationStatus::Failed->value);
    expect($rows[1]->status)->toBe(NotificationStatus::Sent->value);
});

it('suppresses a second send within the dedup window after a successful send', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    // Only one row — the second call short-circuited via the dedup
    // gate (filters on status='sent' within the reminder window).
    $rows = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'expiry_reminder'])
        ->all();

    expect($rows)->toHaveCount(1);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Overwrites the seeded notification template's body with invalid
 * Twig so `View::renderString()` throws on render. Mirrors a
 * production scenario where an admin saves a broken template; the
 * dispatch path's catch block captures the Twig error and writes a
 * failed row.
 */
function breakNotificationTemplate(string $key): void
{
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $service = PasswordPolicy::$plugin->getNotificationTemplates();

    $template = $service->getTemplate($key, $primarySiteId);
    expect($template)->not->toBeNull();

    $template->body = '{% include "absolutely-nonexistent-template-that-throws" %}';
    $service->saveTemplate($template);
}

/**
 * Restores the seeded notification template after `breakNotificationTemplate`
 * mid-test so a subsequent retry can succeed.
 */
function restoreNotificationTemplate(string $key): void
{
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $service = PasswordPolicy::$plugin->getNotificationTemplates();

    $defaults = \craftpulse\passwordpolicy\data\EmailDefaults::all();
    $factory = $defaults[$key] ?? null;
    expect($factory)->not->toBeNull();

    $defaultContent = call_user_func($factory);

    $template = $service->getTemplate($key, $primarySiteId);
    expect($template)->not->toBeNull();

    $template->subject = $defaultContent['subject'];
    $template->body = $defaultContent['body'];
    $service->saveTemplate($template);
}
