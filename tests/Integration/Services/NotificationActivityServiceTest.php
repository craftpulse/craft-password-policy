<?php
/**
 * Pest coverage for `NotificationActivityService` — the read-side
 * companion to `NotificationService`. Pins the read shapes the CP
 * activity index + per-user panel + dashboard failure count depend on:
 * recent-for-user ordering, single-row lookup, distinct-type listing,
 * windowed failure count.
 *
 * Step 4 of the Phase G post-review remediation flipped the storage
 * surface from a plain record to an element-backed table. Pagination
 * is now driven by the native element-index — the service no longer
 * owns a `paginated()` method; the CP controller renders
 * `_layouts/elementindex` directly. Tests adapted accordingly.
 *
 * Rows are seeded via the element save path (paired `craft_elements`
 * row required); no direct INSERT.
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
use craftpulse\passwordpolicy\PasswordPolicy;
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

    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subDays(3));
    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subDays(1));
    seedLogElement($user->id, 'breach_detected', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(2));

    $rows = $this->service->recentForUser($user->id);

    expect($rows)->toHaveCount(3);
    // Newest first
    expect($rows[0]->notificationType)->toBe('breach_detected');
    expect($rows[2]->notificationType)->toBe('expiry_reminder');
});

it('scopes recentForUser strictly to the requested userId', function() {
    $alice = UserFactory::admin();
    $bob = UserFactory::admin();

    seedLogElement($alice->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogElement($bob->id, 'expiry_reminder', NotificationStatus::Sent);

    $rows = $this->service->recentForUser($alice->id);

    expect($rows)->toHaveCount(1);
    expect($rows[0]->userId)->toBe($alice->id);
});

it('caps recentForUser at the configured limit', function() {
    $user = UserFactory::admin();

    for ($i = 0; $i < 15; $i++) {
        seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subMinutes($i));
    }

    expect($this->service->recentForUser($user->id, 5))->toHaveCount(5);
    expect($this->service->recentForUser($user->id))->toHaveCount(NotificationActivityService::DEFAULT_PER_USER_LIMIT);
});

// =============================================================================
// getById — null on miss, hydrated element on hit
// =============================================================================

it('returns null when getById misses', function() {
    expect($this->service->getById(999999))->toBeNull();
});

it('returns the hydrated element on getById hit', function() {
    $user = UserFactory::admin();

    $seed = seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent);

    $found = $this->service->getById((int)$seed->id);

    expect($found)->not->toBeNull();
    expect($found->id)->toBe($seed->id);
});

// =============================================================================
// knownTypes — distinct, sorted
// =============================================================================

it('returns distinct sorted notificationType values', function() {
    $user = UserFactory::admin();

    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent);
    seedLogElement($user->id, 'breach_detected', NotificationStatus::Sent);
    seedLogElement($user->id, 'admin_alert_breach', NotificationStatus::Sent);

    $types = $this->service->knownTypes();

    expect($types)->toEqual(['admin_alert_breach', 'breach_detected', 'expiry_reminder']);
});

// =============================================================================
// recentFailureCount — windowed scope
// =============================================================================

it('counts only failed rows within the requested hours-back window', function() {
    $user = UserFactory::admin();

    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(2));
    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(20));
    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Failed, sentAt: Carbon::now('UTC')->subHours(60));
    // Sent rows must NOT count even within the window
    seedLogElement($user->id, 'expiry_reminder', NotificationStatus::Sent, sentAt: Carbon::now('UTC')->subHours(1));

    expect($this->service->recentFailureCount(24))->toBe(2);
    expect($this->service->recentFailureCount(96))->toBe(3);
    expect($this->service->recentFailureCount(1))->toBe(0);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Builds + persists a `NotificationLogElement` so tests can pin row-set
 * shape without going through the mailer. Element save path allocates
 * a `craft_elements` row first; the element's `afterSave()` writes the
 * paired record.
 */
function seedLogElement(
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
): NotificationLogElement {
    $element = new NotificationLogElement();
    $element->userId = $userId;
    $element->notificationType = $type;
    $element->status = $status->value;
    $element->recipientEmail = $recipientEmail;
    $element->siteIdValue = $siteId;
    $element->subject = $subject;
    $element->body = $body;
    $element->errorMessage = $errorMessage;
    $element->resentFromId = $resentFromId;
    $element->sentAt = DateTimeHelper::toDateTime(($sentAt ?? Carbon::now('UTC'))->format('Y-m-d H:i:s'));

    Craft::$app->getElements()->saveElement($element, false);

    return $element;
}
