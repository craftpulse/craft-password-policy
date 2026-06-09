<?php
/**
 * Pest coverage for `NotificationService::resend()` — the admin-
 * triggered re-fire of a previously logged notification. The contract:
 *
 *  - Re-renders the template **fresh** from current state (admin may
 *    have edited the template since the original send) — does NOT
 *    replay the stored snapshot.
 *  - Writes a new element row linked to the original via `resentFromId`.
 *  - Bypasses the dedup gate that normally suppresses a second send
 *    within the reminder window (admin click is an explicit override).
 *  - Returns false (without writing a row) when the row's
 *    `notificationType` isn't resendable — mailer-key paths
 *    (`new_device`, `admin_alert_*`) need the original event payload
 *    that we don't snapshot.
 *
 * Tests adapted in Step 4 of the Phase G post-review remediation:
 * resend() now takes a `NotificationLogElement`, and rows are seeded
 * via the element save path rather than direct INSERT (so the paired
 * `craft_elements` row exists).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\PasswordPolicy;
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

it('writes a new sent element linked to the original via resentFromId', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // Original send — normal pipeline, success.
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogElement $original */
    $original = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->orderBy(['elements.id' => SORT_DESC])
        ->one();

    $dispatched = $this->plugin->getNotification()->resend($original);

    expect($dispatched)->toBeTrue();

    /** @var NotificationLogElement $resent */
    $resent = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->orderBy(['elements.id' => SORT_DESC])
        ->one();

    expect($resent->id)->not->toBe($original->id);
    expect($resent->resentFromId)->toBe((int)$original->id);
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

    /** @var NotificationLogElement $original */
    $original = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->orderBy(['elements.id' => SORT_DESC])
        ->one();

    // Sanity — a normal second call is suppressed by the dedup gate.
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);
    expect((int)NotificationLogElement::find()->userId($user->id)->status(null)->count())->toBe(1);

    // Resend bypasses dedup explicitly.
    $this->plugin->getNotification()->resend($original);

    expect((int)NotificationLogElement::find()->userId($user->id)->status(null)->count())->toBe(2);
});

// =============================================================================
// Resend re-renders fresh — picks up admin template edits
// =============================================================================

it('re-renders the template fresh and reflects post-edit changes', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogElement $original */
    $original = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->orderBy(['elements.id' => SORT_DESC])
        ->one();

    $originalSubject = $original->subject;

    // Admin edits the template.
    overwriteNotificationTemplateSubject('expiry-reminder', 'EDITED — {{ user.username }}');

    $this->plugin->getNotification()->resend($original);

    /** @var NotificationLogElement $resent */
    $resent = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->orderBy(['elements.id' => SORT_DESC])
        ->one();

    expect($resent->subject)->toContain('EDITED');
    expect($resent->subject)->not->toBe($originalSubject);
});

// =============================================================================
// Resend of breach_detected reuses the original detection time
// =============================================================================
//
// `detectedAt` is a historical fact — the breach was detected when the
// original alert fired, not at resend time. resend() reuses the original
// row's `sentAt` for the `detectedAt` token rather than stamping
// `new DateTime('now')`, so the re-rendered email reflects the real
// detection time.

it('reuses the original sentAt as detectedAt when resending a breach alert', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // Seed a breach_detected row with a fixed, clearly-historical sentAt.
    $originalSentAt = DateTimeHelper::toDateTime('2020-01-15 09:30:00');

    $seed = new NotificationLogElement();
    $seed->userId = $user->id;
    $seed->notificationType = 'breach_detected';
    $seed->status = NotificationStatus::Sent->value;
    $seed->recipientEmail = 'recipient@example.test';
    $seed->subject = 'Breach detected';
    $seed->body = 'Body';
    $seed->sentAt = $originalSentAt;
    Craft::$app->getElements()->saveElement($seed, false);

    // Make the rendered body echo the detectedAt token unambiguously so we
    // can assert on the historical date rather than "now".
    overwriteNotificationTemplateSubject('breach-detected', 'Breach at {{ detectedAt|date("Y-m-d") }}');

    $dispatched = $this->plugin->getNotification()->resend($seed);

    expect($dispatched)->toBeTrue();

    /** @var NotificationLogElement $resent */
    $resent = NotificationLogElement::find()
        ->userId($user->id)
        ->notificationType('breach_detected')
        ->status(null)
        ->orderBy(['elements.id' => SORT_DESC])
        ->one();

    // The re-rendered subject reflects the original detection date, NOT
    // the resend timestamp (which would be the current year).
    expect($resent->subject)->toContain('2020-01-15');
    expect($resent->subject)->not->toContain(date('Y'));
});

// =============================================================================
// Resend rejects mailer-key types (new_device, admin_alert_*)
// =============================================================================

it('returns false without writing a row when the type is not resendable', function() {
    $user = UserFactory::admin();

    // Seed a row whose type isn't resendable — `new_device` is a
    // mailer-key path, so the original event payload (deviceLabel,
    // maskedIp) isn't snapshotted in the log. Goes through the
    // element save path so the paired `craft_elements` row exists.
    $seed = new NotificationLogElement();
    $seed->userId = $user->id;
    $seed->notificationType = 'new_device';
    $seed->status = NotificationStatus::Sent->value;
    $seed->recipientEmail = 'recipient@example.test';
    $seed->subject = 'New device';
    $seed->body = 'Body';
    $seed->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));

    Craft::$app->getElements()->saveElement($seed, false);

    /** @var NotificationLogElement $row */
    $row = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->one();

    $rowsBefore = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();

    $dispatched = $this->plugin->getNotification()->resend($row);

    expect($dispatched)->toBeFalse();

    $rowsAfter = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();

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
