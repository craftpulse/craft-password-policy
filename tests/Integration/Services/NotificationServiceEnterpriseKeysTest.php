<?php
/**
 * Pest coverage for the G12 conversion of `new-device-alert` and
 * `admin-security-alert` from the `composeFromKey()` mailer-templates
 * path onto the editable-templates surface (`_dispatch()`).
 *
 * Pre-G12 both keys called `Craft::$app->getMailer()->composeFromKey()`
 * against mailer keys that were never registered via
 * `SystemMessages::EVENT_REGISTER_MESSAGES`, so the resulting emails
 * rendered empty or threw. G12 moved both to the editable-templates
 * surface with seeded defaults from `EmailDefaults`, full subject + body
 * capture on the log row, and a unified dispatch path that also
 * supports admin-recipient sends (no `$user`).
 *
 * This file pins:
 *  - `sendNewDeviceAlert()` writes a `sent` row with non-empty rendered
 *    subject + body, scoped to the recipient user.
 *  - `sendAdminSecurityAlert()` writes a `sent` row with non-empty
 *    rendered subject + body, `userId = null`, recipient set to the
 *    configured `adminAlertEmail` setting.
 *  - Failure path: when the template body is invalid Twig, the write
 *    captures `status = failed` with `errorMessage` populated (audit
 *    invariant from F2 carries forward unchanged for both new keys).
 *  - `resend()` rejects both `new_device` and `admin_alert_*` types —
 *    the inputs (`deviceLabel` / `maskedIp` / event `context`) aren't
 *    snapshotted on the log row so a fresh render isn't possible. A
 *    future `templateVarsJson` column would unlock resend (additive
 *    future work, not part of G12).
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
use craftpulse\passwordpolicy\exceptions\EditionRequiredException;
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

    $this->settings = $this->plugin->getSettings();
    $this->originalAdminAlertEmail = $this->settings->adminAlertEmail;
    $this->originalAdminAlertEvents = $this->settings->adminAlertEvents;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->adminAlertEmail = $this->originalAdminAlertEmail;
    $this->settings->adminAlertEvents = $this->originalAdminAlertEvents;
});

// =============================================================================
// new-device-alert — happy path through _dispatch()
// =============================================================================

it('dispatches new-device-alert with rendered subject + body captured', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendNewDeviceAlert(
        $user,
        'Chrome on macOS',
        '192.168.x.x',
    );

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'new_device'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Sent->value);
    expect($row->notificationType)->toBe('new_device');
    expect($row->recipientEmail)->toBe('recipient@example.test');
    expect($row->errorMessage)->toBeNull();
    // Subject + body are populated with rendered Twig output —
    // EmailDefaults::newDeviceAlert() references `{{ siteName }}`,
    // `{{ deviceLabel }}`, and `{{ maskedIp }}` tokens that resolve
    // at send. We don't pin exact strings (defaults may be re-worded
    // without a behavior change), just non-null/non-empty.
    expect($row->subject)->not->toBeNull();
    expect($row->subject)->not->toBe('');
    expect($row->body)->not->toBeNull();
    expect($row->body)->not->toBe('');
    // Token substitution actually happened — tokens themselves shouldn't
    // appear in the rendered output.
    expect($row->body)->toContain('Chrome on macOS');
    expect($row->body)->toContain('192.168.x.x');
});

// =============================================================================
// admin-security-alert — happy path with userId=null
// =============================================================================

it('dispatches admin-security-alert with rendered subject + body captured', function() {
    // Admin security alerts are an Enterprise surface — the service throws
    // EditionRequiredException below the Enterprise tier.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->adminAlertEmail = 'ops@example.test';
    $this->settings->adminAlertEvents = null; // null = all events trigger

    $this->plugin->getNotification()->sendAdminSecurityAlert(
        'breach_detected',
        ['userId' => 7, 'email' => 'compromised@example.test'],
    );

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['notificationType' => 'admin_alert_breach_detected'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Sent->value);
    expect($row->notificationType)->toBe('admin_alert_breach_detected');
    // Admin alerts have userId = null (operator inbox, not end-user).
    expect($row->userId)->toBeNull();
    expect($row->recipientEmail)->toBe('ops@example.test');
    expect($row->errorMessage)->toBeNull();
    expect($row->subject)->not->toBeNull();
    expect($row->subject)->not->toBe('');
    expect($row->body)->not->toBeNull();
    expect($row->body)->not->toBe('');
    // Event token substituted into both subject + body.
    expect($row->subject)->toContain('breach_detected');
    expect($row->body)->toContain('breach_detected');
});

// =============================================================================
// Edition gate — admin-security-alert is Enterprise-only
// =============================================================================
//
// The service-layer gate throws EditionRequiredException below Enterprise
// (defense-in-depth: the driving caller registers on Enterprise only, but a
// config override or direct caller must not bypass the edition tier). This
// matches the Pro gates on sendBreachDetected() / sendNewDeviceAlert().

it('throws EditionRequiredException for admin-security-alert on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->adminAlertEmail = 'ops@example.test';
    $this->settings->adminAlertEvents = null;

    $this->plugin->getNotification()->sendAdminSecurityAlert('breach_detected', ['userId' => 7]);
})->throws(EditionRequiredException::class);

it('throws EditionRequiredException for admin-security-alert on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->adminAlertEmail = 'ops@example.test';
    $this->settings->adminAlertEvents = null;

    $this->plugin->getNotification()->sendAdminSecurityAlert('breach_detected', ['userId' => 7]);
})->throws(EditionRequiredException::class);

// =============================================================================
// Missing-template branch writes a captured `failed` row
// =============================================================================
//
// The dedup gate (`shouldFire()`) records the fire on the dispatch ATTEMPT,
// so a silent return on a missing template would suppress every retry for
// the cooldown window with no operator-visible trail. _dispatch() now writes
// a `status = failed` row on the missing-template branch, honouring the
// capture invariant (every dispatch attempt writes a row).

it('writes a failed row when the template row is missing', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // Delete the seeded expiry-reminder row so the dispatch finds no
    // template — the missing-template branch must still capture a row.
    deleteNotificationTemplate('expiry-reminder');

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'expiry_reminder'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Failed->value);
    expect($row->recipientEmail)->toBe('recipient@example.test');
    expect($row->subject)->toBeNull();
    expect($row->body)->toBeNull();
    expect($row->errorMessage)->not->toBeNull();
    expect($row->errorMessage)->toContain('template');
});

// =============================================================================
// Failure path — broken template Twig triggers captured `failed` row
// =============================================================================

it('captures a failed row for new-device-alert when template rendering throws', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    breakEnterpriseTemplate('new-device-alert');

    $this->plugin->getNotification()->sendNewDeviceAlert(
        $user,
        'Chrome on macOS',
        '192.168.x.x',
    );

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'new_device'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Failed->value);
    expect($row->recipientEmail)->toBe('recipient@example.test');
    expect($row->errorMessage)->not->toBeNull();
    expect($row->errorMessage)->not->toBe('');
});

it('captures a failed row for admin-security-alert when template rendering throws', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->adminAlertEmail = 'ops@example.test';
    $this->settings->adminAlertEvents = null;

    breakEnterpriseTemplate('admin-security-alert');

    // Distinct event name from the happy-path test above. The
    // `AlertCooldownService` cache key is keyed by event, and the
    // cache (`Craft::$app->getCache()`) survives the per-test DB
    // transaction rollback — using a fresh event name avoids a cache
    // hit suppressing this dispatch.
    $this->plugin->getNotification()->sendAdminSecurityAlert(
        'lockout',
        ['userId' => 7],
    );

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['notificationType' => 'admin_alert_lockout'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Failed->value);
    expect($row->userId)->toBeNull();
    expect($row->recipientEmail)->toBe('ops@example.test');
    expect($row->errorMessage)->not->toBeNull();
    expect($row->errorMessage)->not->toBe('');
});

// =============================================================================
// Resend is rejected — `templateVarsJson` snapshot is future work
// =============================================================================

it('returns false from resend() for new_device and admin_alert_* types', function() {
    $user = UserFactory::admin();
    $now = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));

    // Seed two rows — one new_device, one admin_alert_* — both with
    // `status = sent` so a failed-row filter doesn't mask the rejection.
    // Goes through the element save path so the paired `craft_elements`
    // row exists.
    $newDeviceRow = new NotificationLogElement();
    $newDeviceRow->userId = $user->id;
    $newDeviceRow->notificationType = 'new_device';
    $newDeviceRow->status = NotificationStatus::Sent->value;
    $newDeviceRow->recipientEmail = 'recipient@example.test';
    $newDeviceRow->subject = 'New device';
    $newDeviceRow->body = 'Body';
    $newDeviceRow->sentAt = $now;
    Craft::$app->getElements()->saveElement($newDeviceRow, false);

    $adminAlertRow = new NotificationLogElement();
    $adminAlertRow->userId = null;
    $adminAlertRow->notificationType = 'admin_alert_breach_detected';
    $adminAlertRow->status = NotificationStatus::Sent->value;
    $adminAlertRow->recipientEmail = 'ops@example.test';
    $adminAlertRow->subject = 'Security alert';
    $adminAlertRow->body = 'Body';
    $adminAlertRow->sentAt = $now;
    Craft::$app->getElements()->saveElement($adminAlertRow, false);

    $rowsBefore = (int)NotificationLogElement::find()->status(null)->count();

    expect($this->plugin->getNotification()->resend($newDeviceRow))->toBeFalse();
    expect($this->plugin->getNotification()->resend($adminAlertRow))->toBeFalse();

    $rowsAfter = (int)NotificationLogElement::find()->status(null)->count();

    // No new rows — both calls short-circuited via
    // `_templateKeyForType()` returning null.
    expect($rowsAfter)->toBe($rowsBefore);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Overwrites the seeded notification template's body with invalid Twig so
 * `View::renderString()` throws on render. Mirrors a production scenario
 * where an admin saves a broken template; the dispatch path's catch block
 * captures the Twig error and writes a failed row.
 *
 * Distinct helper name from `breakNotificationTemplate()` in
 * `NotificationServiceCaptureTest.php` — Pest's file-helper scope can
 * collide across files when both are loaded in the same suite run.
 */
function breakEnterpriseTemplate(string $key): void
{
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $service = PasswordPolicy::$plugin->getNotificationTemplates();

    $template = $service->getTemplate($key, $primarySiteId);
    expect($template)->not->toBeNull();

    $template->body = '{% include "absolutely-nonexistent-template-that-throws" %}';
    $service->saveTemplate($template);
}

/**
 * Deletes every template row for a notification key (all sites) so the
 * dispatch path's `getTemplate()` lookup returns null — exercising the
 * missing-template branch of `_dispatch()`. `getTemplate()` falls back to
 * the primary-site row, so a per-site delete alone wouldn't make the
 * template truly absent; we clear all rows for the key.
 */
function deleteNotificationTemplate(string $key): void
{
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_notification_templates}}', ['notificationKey' => $key])
        ->execute();
}
