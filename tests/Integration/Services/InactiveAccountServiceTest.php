<?php
/**
 * Pest coverage for `InactiveAccountService` — the Feature 5 (Pro)
 * detection query + the three action modes.
 *
 * Pins:
 *
 *  - `findInactiveUsers()` flags an account whose `lastLoginDate` is just
 *    OUTSIDE the threshold and skips one just INSIDE (boundary).
 *  - A never-logged-in account falls back to `dateCreated` — aged
 *    `dateCreated` flags, fresh `dateCreated` does not.
 *  - An already-suspended account is excluded (no point re-suspending).
 *  - `applyAction('report', …)` is a pure no-op — no suspension, no email.
 *  - `applyAction('suspend', …)` flips Craft's native `suspended` flag.
 *  - `applyAction('notify', …)` sends through `NotificationService`
 *    (a `notification_log` row is written) and leaves `suspended` alone.
 *
 * Detection runs on Pro — the service has no edition gate of its own, but
 * the notify path's `NotificationService::sendInactiveAccount()` is
 * Pro-gated, so the suite elevates to Pro in `beforeEach`.
 *
 * Direct DB writes back-date `lastLoginDate` / `dateCreated` / `suspended`
 * because `User::find()` doesn't expose `lastLoginDate` for write and the
 * factory can't easily age a user.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
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
    $this->service = $this->plugin->getInactiveAccounts();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

function setUserDates(int $userId, ?string $lastLogin, string $dateCreated): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            [
                'lastLoginDate' => $lastLogin,
                'dateCreated' => $dateCreated,
            ],
            ['id' => $userId],
        )
        ->execute();
}

function inactiveIds(int $thresholdDays): array
{
    return PasswordPolicy::$plugin->getInactiveAccounts()
        ->findInactiveUsers($thresholdDays)
        ->column();
}

// =============================================================================
// findInactiveUsers — threshold boundary on lastLoginDate
// =============================================================================

it('flags an account whose last login is just outside the threshold', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');
    setUserDates(
        (int)$user->id,
        $now->copy()->subDays(91)->format('Y-m-d H:i:s'),
        $now->copy()->subDays(91)->format('Y-m-d H:i:s'),
    );

    expect(inactiveIds(90))->toContain((int)$user->id);
});

it('does not flag an account whose last login is just inside the threshold', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');
    setUserDates(
        (int)$user->id,
        $now->copy()->subDays(89)->format('Y-m-d H:i:s'),
        $now->copy()->subDays(200)->format('Y-m-d H:i:s'),
    );

    expect(inactiveIds(90))->not->toContain((int)$user->id);
});

// =============================================================================
// findInactiveUsers — never-logged-in falls back to dateCreated
// =============================================================================

it('falls back to dateCreated for a never-logged-in account', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');
    // No lastLoginDate, but dateCreated aged past the threshold.
    setUserDates(
        (int)$user->id,
        null,
        $now->copy()->subDays(120)->format('Y-m-d H:i:s'),
    );

    expect(inactiveIds(90))->toContain((int)$user->id);
});

it('does not flag a fresh never-logged-in account', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');
    setUserDates(
        (int)$user->id,
        null,
        $now->copy()->subDays(10)->format('Y-m-d H:i:s'),
    );

    expect(inactiveIds(90))->not->toContain((int)$user->id);
});

// =============================================================================
// findInactiveUsers — already-suspended excluded
// =============================================================================

it('excludes an already-suspended account', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');
    setUserDates(
        (int)$user->id,
        $now->copy()->subDays(200)->format('Y-m-d H:i:s'),
        $now->copy()->subDays(200)->format('Y-m-d H:i:s'),
    );
    Craft::$app->getDb()->createCommand()
        ->update(Table::USERS, ['suspended' => true], ['id' => $user->id])
        ->execute();

    expect(inactiveIds(90))->not->toContain((int)$user->id);
});

// =============================================================================
// findInactiveUsers — non-positive threshold matches nothing
// =============================================================================

it('matches nothing for a non-positive threshold', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');
    setUserDates(
        (int)$user->id,
        $now->copy()->subDays(500)->format('Y-m-d H:i:s'),
        $now->copy()->subDays(500)->format('Y-m-d H:i:s'),
    );

    expect(inactiveIds(0))->toBe([]);
});

// =============================================================================
// applyAction — report is a pure no-op
// =============================================================================

it('does not suspend or notify in report mode', function() {
    $user = UserFactory::admin();
    $user->email = 'dormant-report@example.test';

    $this->service->applyAction($user, 'report');

    $reloaded = Craft::$app->getUsers()->getUserById((int)$user->id);
    expect($reloaded->suspended)->toBeFalse();

    $row = NotificationLogRecord::find()->where(['userId' => $user->id])->one();
    expect($row)->toBeNull();
});

// =============================================================================
// applyAction — suspend flips the native flag
// =============================================================================

it('suspends the user in suspend mode', function() {
    $user = UserFactory::admin();

    $this->service->applyAction($user, 'suspend');

    $reloaded = Craft::$app->getUsers()->getUserById((int)$user->id);
    expect($reloaded->suspended)->toBeTrue();
})->skip(fn() => Craft::$app->edition->value < \craft\enums\CmsEdition::Pro->value, 'needs multi-user edition');

// =============================================================================
// applyAction — notify sends through NotificationService, no suspension
// =============================================================================

it('sends a notification and does not suspend in notify mode', function() {
    $user = UserFactory::admin();
    $user->email = 'dormant-notify@example.test';
    Craft::$app->getElements()->saveElement($user);

    $this->service->applyAction($user, 'notify');

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
