<?php
/**
 * Pest coverage for `NotificationLogElement` + `NotificationLogQuery`.
 * Verifies the element-record pairing, status filtering, custom query
 * params, and read shapes the activity surface depends on.
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
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Element-record pairing — element id IS record id IS craft_elements.id
// =============================================================================

it('saves and re-queries an element via the element pipeline', function() {
    $user = UserFactory::admin();

    $element = new NotificationLogElement();
    $element->userId = $user->id;
    $element->notificationType = 'expiry_reminder';
    $element->status = NotificationStatus::Sent->value;
    $element->recipientEmail = 'test@example.test';
    $element->subject = 'Subject';
    $element->body = 'Body';
    $element->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));

    $saved = Craft::$app->getElements()->saveElement($element, false);

    expect($saved)->toBeTrue();
    expect($element->id)->not->toBeNull();

    $found = NotificationLogElement::find()
        ->id($element->id)
        ->status(null)
        ->one();

    expect($found)->not->toBeNull();
    expect($found->notificationType)->toBe('expiry_reminder');
    expect($found->status)->toBe('sent');
    expect($found->recipientEmail)->toBe('test@example.test');
});

it('persists a paired NotificationLogRecord with the same id', function() {
    $user = UserFactory::admin();

    $element = new NotificationLogElement();
    $element->userId = $user->id;
    $element->notificationType = 'breach_detected';
    $element->status = NotificationStatus::Failed->value;
    $element->errorMessage = 'transient failure';
    $element->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));

    Craft::$app->getElements()->saveElement($element, false);

    /** @var NotificationLogRecord|null $record */
    $record = NotificationLogRecord::findOne($element->id);

    expect($record)->not->toBeNull();
    expect((int)$record->id)->toBe((int)$element->id);
    expect($record->notificationType)->toBe('breach_detected');
    expect($record->status)->toBe('failed');
    expect($record->errorMessage)->toBe('transient failure');
});

// =============================================================================
// Element-index status filtering
// =============================================================================

it('filters by element-index status (sent / failed)', function() {
    $user = UserFactory::admin();

    seedElement($user->id, NotificationStatus::Sent);
    seedElement($user->id, NotificationStatus::Sent);
    seedElement($user->id, NotificationStatus::Failed);

    $sent = NotificationLogElement::find()->userId($user->id)->status(NotificationStatus::Sent->value)->all();
    $failed = NotificationLogElement::find()->userId($user->id)->status(NotificationStatus::Failed->value)->all();
    $all = NotificationLogElement::find()->userId($user->id)->status(null)->all();

    expect($sent)->toHaveCount(2);
    expect($failed)->toHaveCount(1);
    expect($all)->toHaveCount(3);
});

// =============================================================================
// Custom query params
// =============================================================================

it('filters by notificationType', function() {
    $user = UserFactory::admin();

    seedElement($user->id, NotificationStatus::Sent, type: 'expiry_reminder');
    seedElement($user->id, NotificationStatus::Sent, type: 'breach_detected');

    $results = NotificationLogElement::find()
        ->userId($user->id)
        ->notificationType('breach_detected')
        ->status(null)
        ->all();

    expect($results)->toHaveCount(1);
    expect($results[0]->notificationType)->toBe('breach_detected');
});

it('filters by resentFromId', function() {
    $user = UserFactory::admin();

    $original = seedElement($user->id, NotificationStatus::Sent);
    seedElement($user->id, NotificationStatus::Sent, resentFromId: (int)$original->id);

    $results = NotificationLogElement::find()
        ->userId($user->id)
        ->resentFromId($original->id)
        ->status(null)
        ->all();

    expect($results)->toHaveCount(1);
    expect($results[0]->resentFromId)->toBe((int)$original->id);
});

it('filters by sentAfter and sentBefore datetime params', function() {
    $user = UserFactory::admin();

    $old = DateTimeHelper::toDateTime(Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s'));
    $mid = DateTimeHelper::toDateTime(Carbon::now('UTC')->subDays(5)->format('Y-m-d H:i:s'));
    $recent = DateTimeHelper::toDateTime(Carbon::now('UTC')->subHours(1)->format('Y-m-d H:i:s'));

    seedElement($user->id, NotificationStatus::Sent, sentAt: $old);
    seedElement($user->id, NotificationStatus::Sent, sentAt: $mid);
    seedElement($user->id, NotificationStatus::Sent, sentAt: $recent);

    $afterOld = NotificationLogElement::find()
        ->userId($user->id)
        ->sentAfter(DateTimeHelper::toDateTime(Carbon::now('UTC')->subDays(7)->format('Y-m-d H:i:s')))
        ->status(null)
        ->all();
    $beforeOld = NotificationLogElement::find()
        ->userId($user->id)
        ->sentBefore(DateTimeHelper::toDateTime(Carbon::now('UTC')->subDays(7)->format('Y-m-d H:i:s')))
        ->status(null)
        ->all();

    expect($afterOld)->toHaveCount(2);
    expect($beforeOld)->toHaveCount(1);
});

// =============================================================================
// Soft-delete + restore
// =============================================================================

it('soft-deletes via the element pipeline (Restore source recoverable)', function() {
    $user = UserFactory::admin();

    $element = seedElement($user->id, NotificationStatus::Sent);
    $id = $element->id;

    Craft::$app->getElements()->deleteElement($element);

    $foundLive = NotificationLogElement::find()->id($id)->status(null)->one();
    $foundTrashed = NotificationLogElement::find()->id($id)->status(null)->trashed()->one();

    expect($foundLive)->toBeNull();
    expect($foundTrashed)->not->toBeNull();

    // Record row survives because element soft-delete sets `dateDeleted`
    // on craft_elements but doesn't drop the notification_log row.
    /** @var NotificationLogRecord|null $record */
    $record = NotificationLogRecord::findOne($id);
    expect($record)->not->toBeNull();
});

// =============================================================================
// isResendable — type-driven gate
// =============================================================================

it('marks editable-template types as resendable', function() {
    $user = UserFactory::admin();

    $expiry = seedElement($user->id, NotificationStatus::Sent, type: 'expiry_reminder');
    $breach = seedElement($user->id, NotificationStatus::Sent, type: 'breach_detected');
    $device = seedElement($user->id, NotificationStatus::Sent, type: 'new_device');
    $admin = seedElement($user->id, NotificationStatus::Sent, type: 'admin_alert_breach');

    expect($expiry->isResendable())->toBeTrue();
    expect($breach->isResendable())->toBeTrue();
    expect($device->isResendable())->toBeFalse();
    expect($admin->isResendable())->toBeFalse();
});

// =============================================================================
// userId nullability — audit row outlives the user
// =============================================================================

it('accepts a null userId for admin-alert rows', function() {
    $element = new NotificationLogElement();
    $element->userId = null;
    $element->notificationType = 'admin_alert_breach';
    $element->status = NotificationStatus::Sent->value;
    $element->recipientEmail = 'admin@example.test';
    $element->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));

    $saved = Craft::$app->getElements()->saveElement($element, false);

    expect($saved)->toBeTrue();
    $found = NotificationLogElement::find()->id($element->id)->status(null)->one();
    expect($found)->not->toBeNull();
    expect($found->userId)->toBeNull();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Builds + persists a `NotificationLogElement` so tests can pin
 * query shape without going through the mailer. Element save path
 * allocates a `craft_elements` row first; the element's `afterSave()`
 * writes the paired record.
 */
function seedElement(
    int $userId,
    NotificationStatus $status,
    string $type = 'expiry_reminder',
    ?DateTime $sentAt = null,
    ?int $resentFromId = null,
): NotificationLogElement {
    $element = new NotificationLogElement();
    $element->userId = $userId;
    $element->notificationType = $type;
    $element->status = $status->value;
    $element->recipientEmail = 'test@example.test';
    $element->subject = 'Subject';
    $element->body = 'Body';
    $element->resentFromId = $resentFromId;
    $element->sentAt = $sentAt ?? DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s'));

    Craft::$app->getElements()->saveElement($element, false);

    return $element;
}
