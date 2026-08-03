<?php
/**
 * Pest coverage for the Feature 3 per-group alert dispatch seam
 * (`PasswordPolicy::_dispatchGroupAlerts()`), driven through the new-device
 * login listener (`yii\web\User::EVENT_AFTER_LOGIN`).
 *
 * Pins:
 *
 *  - A login from a new device by a user IN a subscribed group routes a copy
 *    of the alert to the group security contact — a
 *    `group_alert_new_device` notification-log row addressed to that contact.
 *  - The copy is in ADDITION to the end-user's own `new_device` alert (both
 *    rows exist on Enterprise + `enableNewDeviceAlerts`).
 *  - A user NOT in any subscribed group routes NO group copy.
 *  - The per-group cooldown suppresses a second copy for another member of
 *    the SAME group inside the window.
 *  - Routing is Pro-gated: on Lite, no group copy even with a subscription.
 *
 * Uses the WebRequestStub + `User::find()` fresh-load pattern (the element
 * identity cache memoizes an empty `_groups` on the original instance after
 * `assignUserToGroups`).
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\GroupAlertSubscriptionRecord;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\base\Event;
use yii\web\User as WebUser;
use yii\web\UserEvent as WebUserEvent;

const GAD_CHROME_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableNewDeviceAlerts = $this->settings->enableNewDeviceAlerts;
    $this->originalRequest = Craft::$app->getRequest();

    $request = new WebRequestStub();
    $request->stubUserAgent = GAD_CHROME_MAC_UA;
    $request->stubUserIp = '203.0.113.45';
    $request->stubIsCpRequest = true;
    Craft::$app->set('request', $request);

    GroupAlertSubscriptionRecord::deleteAll();
    Craft::$app->getCache()->flush();

    $this->group = GroupFactory::create();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    $this->plugin->edition = $this->originalEdition;
    $this->settings->enableNewDeviceAlerts = $this->originalEnableNewDeviceAlerts;
});

// =============================================================================
// Helpers
// =============================================================================

function fireGroupAlertLogin(User $user): void
{
    Event::trigger(
        WebUser::class,
        WebUser::EVENT_AFTER_LOGIN,
        new WebUserEvent(['identity' => $user]),
    );
}

function memberOfGroup(int $groupId): User
{
    $user = UserFactory::nonAdmin();
    Craft::$app->getUsers()->assignUserToGroups($user->id, [$groupId]);
    // Fresh load — `getGroups()` memoizes empty on the original instance.
    return User::find()->id($user->id)->one();
}

function groupAlertLogRowsTo(string $email): array
{
    return NotificationLogRecord::find()
        ->where(['notificationType' => 'group_alert_new_device', 'recipientEmail' => $email])
        ->all();
}

function seedGroupAlertSubscription(int $groupId, string $eventType, string $email): void
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    $record = new GroupAlertSubscriptionRecord();
    $record->groupId = $groupId;
    $record->eventType = $eventType;
    $record->recipientEmail = $email;
    $record->enabled = true;
    $record->dateCreated = $now;
    $record->dateUpdated = $now;
    $record->uid = StringHelper::UUID();
    $record->save(false);
}

// =============================================================================
// In-group user → group security contact receives a copy
// =============================================================================

it('routes a group alert copy when an in-group user triggers a new device', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    seedGroupAlertSubscription((int)$this->group->id, 'new_device', 'group-contact@craftpulse.test');

    $user = memberOfGroup((int)$this->group->id);

    fireGroupAlertLogin($user);

    expect(groupAlertLogRowsTo('group-contact@craftpulse.test'))->toHaveCount(1);
});

// =============================================================================
// Out-of-group user → no group copy
// =============================================================================

it('does not route a group alert copy for an out-of-group user', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    seedGroupAlertSubscription((int)$this->group->id, 'new_device', 'group-contact@craftpulse.test');

    // A different group with no subscription.
    $otherGroup = GroupFactory::create();
    $user = memberOfGroup((int)$otherGroup->id);

    fireGroupAlertLogin($user);

    expect(groupAlertLogRowsTo('group-contact@craftpulse.test'))->toHaveCount(0);
});

// =============================================================================
// Cooldown — a second member of the same group inside the window is suppressed
// =============================================================================

it('suppresses a second group alert copy for the same group inside the cooldown window', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    seedGroupAlertSubscription((int)$this->group->id, 'new_device', 'group-contact@craftpulse.test');

    // Two distinct members of the same subscribed group, both first-seen
    // devices, inside the per-group cooldown window.
    $userA = memberOfGroup((int)$this->group->id);
    $userB = memberOfGroup((int)$this->group->id);

    fireGroupAlertLogin($userA);
    fireGroupAlertLogin($userB);

    // Two end-user device rows, but only ONE copy to the group contact.
    expect(groupAlertLogRowsTo('group-contact@craftpulse.test'))->toHaveCount(1);
});

// =============================================================================
// Lite — routing is Pro-gated; no group copy even with a subscription
// =============================================================================

it('does not route a group alert copy on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    seedGroupAlertSubscription((int)$this->group->id, 'new_device', 'group-contact@craftpulse.test');

    $user = memberOfGroup((int)$this->group->id);

    fireGroupAlertLogin($user);

    expect(groupAlertLogRowsTo('group-contact@craftpulse.test'))->toHaveCount(0);
});
