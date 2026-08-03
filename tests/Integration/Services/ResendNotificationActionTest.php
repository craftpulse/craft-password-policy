<?php
/**
 * Pest coverage for `ResendNotification` element action — the bulk
 * "Resend" affordance on the notification-log element index.
 *
 * The action delegates per-row to
 * `NotificationService::resend()`, so the contract here is narrow:
 *
 *  - Bulk-resend across a mixed query: resendable types fire a new
 *    element row chained via `resentFromId`; mailer-key types skip
 *    (return false from the service); the action returns true overall.
 *  - When every selected row is non-resendable, the action returns
 *    false with a useful message.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\elements\actions\ResendNotification;
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
// Bulk resend across resendable rows
// =============================================================================

it('resends each resendable row in the query and writes new chained elements', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // Seed two resendable rows via the natural pipeline.
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    $second = new NotificationLogElement();
    $second->userId = $user->id;
    $second->notificationType = 'breach_detected';
    $second->status = NotificationStatus::Sent->value;
    $second->recipientEmail = 'recipient@example.test';
    $second->subject = 'Original breach';
    $second->body = 'Body';
    $second->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));
    Craft::$app->getElements()->saveElement($second, false);

    $countBefore = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();

    $action = new ResendNotification();
    $query = NotificationLogElement::find()->userId($user->id)->status(null);

    $result = $action->performAction($query);

    expect($result)->toBeTrue();

    $countAfter = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();
    // Two original rows + two resend rows.
    expect($countAfter)->toBe($countBefore + 2);

    // Verify each resend has a resentFromId chained to an original.
    $resends = NotificationLogElement::find()
        ->userId($user->id)
        ->status(null)
        ->resentFromId(['not', null])
        ->all();

    expect($resends)->toHaveCount(2);
});

// =============================================================================
// Skips mailer-key rows but still reports success when any row succeeded
// =============================================================================

it('reports skipped count when mixed with resendable rows', function() {
    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    // One resendable + one non-resendable.
    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    $deviceRow = new NotificationLogElement();
    $deviceRow->userId = $user->id;
    $deviceRow->notificationType = 'new_device';
    $deviceRow->status = NotificationStatus::Sent->value;
    $deviceRow->recipientEmail = 'recipient@example.test';
    $deviceRow->subject = 'New device';
    $deviceRow->body = 'Body';
    $deviceRow->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));
    Craft::$app->getElements()->saveElement($deviceRow, false);

    $countBefore = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();

    $action = new ResendNotification();
    $query = NotificationLogElement::find()->userId($user->id)->status(null);

    $result = $action->performAction($query);

    expect($result)->toBeTrue();

    $countAfter = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();
    // Two before + one resend (only the expiry_reminder fires).
    expect($countAfter)->toBe($countBefore + 1);
});

// =============================================================================
// All-skipped case — returns false with a message
// =============================================================================

it('returns false when every selected row is non-resendable', function() {
    $user = UserFactory::admin();

    $deviceRow = new NotificationLogElement();
    $deviceRow->userId = $user->id;
    $deviceRow->notificationType = 'new_device';
    $deviceRow->status = NotificationStatus::Sent->value;
    $deviceRow->recipientEmail = 'recipient@example.test';
    $deviceRow->subject = 'New device';
    $deviceRow->body = 'Body';
    $deviceRow->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));
    Craft::$app->getElements()->saveElement($deviceRow, false);

    $countBefore = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();

    $action = new ResendNotification();
    $query = NotificationLogElement::find()->userId($user->id)->status(null);

    $result = $action->performAction($query);

    expect($result)->toBeFalse();

    $countAfter = (int)NotificationLogElement::find()->userId($user->id)->status(null)->count();
    expect($countAfter)->toBe($countBefore);
});
