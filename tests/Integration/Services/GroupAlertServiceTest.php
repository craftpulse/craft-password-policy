<?php
/**
 * Pest coverage for `GroupAlertService` — the Feature 3 per-group alert
 * subscription read + write path.
 *
 * Pins the per-group-resolution invariant
 * (`project_per_group_resolution_hazard.md`):
 *
 *  - A user in two subscribed groups gets the UNION of the recipients, each
 *    distinct contact ONCE (dedup across the user's resolved group set).
 *  - A disabled subscription is excluded from recipient resolution.
 *  - A user in NONE of the subscribed groups resolves to an empty set.
 *  - `recipientsForUser()` resolves from the user's ACTUAL group membership
 *    (`getGroups()`), so moving a user between groups changes the resolved
 *    recipients without touching the subscription rows.
 *  - `saveSubscriptions()` applies blocklist-style diff-on-save: kept rows
 *    survive, removed rows delete, new rows insert.
 *
 * Storage is edition-independent — these run on whatever edition the
 * playground is at (the GroupFactory elevates the Craft license to Pro for
 * group saves; the plugin service itself has no edition gate).
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\GroupAlertSubscriptionRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getGroupAlerts();

    // Clean slate — the table is global, not per-user.
    GroupAlertSubscriptionRecord::deleteAll();

    $this->groupA = GroupFactory::create();
    $this->groupB = GroupFactory::create();
    $this->groupC = GroupFactory::create();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts a single subscription row directly. `saveSubscriptions()` is a
 * full-replace (the editor contract), so it cannot be used to accumulate
 * seed rows — a second call would delete the first. Seed rows go in via the
 * record so the read-path tests are exercised against a known fixture.
 */
function seedSubscription(int $groupId, string $eventType, string $email, bool $enabled = true): void
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    $record = new GroupAlertSubscriptionRecord();
    $record->groupId = $groupId;
    $record->eventType = $eventType;
    $record->recipientEmail = $email;
    $record->enabled = $enabled;
    $record->dateCreated = $now;
    $record->dateUpdated = $now;
    $record->uid = StringHelper::UUID();
    $record->save(false);
}

function userInGroups(array $groupIds): \craft\elements\User
{
    $user = UserFactory::nonAdmin();
    Craft::$app->getUsers()->assignUserToGroups($user->id, $groupIds);

    // `assignUserToGroups` populates the junction table, but the original
    // element instance memoizes an empty `_groups`. A FRESH `User::find()`
    // query (not `getUserById`, which hits the element identity cache) is
    // needed so `getGroups()` reflects the assignment — mirrors the
    // `persistGroupMembership` note in ProCellRenderingTest.
    return \craft\elements\User::find()->id($user->id)->one();
}

// =============================================================================
// recipientsForUser — UNION across the user's resolved groups, de-duplicated
// =============================================================================

it('returns the union of recipients across the user resolved group set', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'sec-a@craftpulse.test');
    seedSubscription((int)$this->groupB->id, 'breach_detected', 'sec-b@craftpulse.test');

    $user = userInGroups([(int)$this->groupA->id, (int)$this->groupB->id]);

    $recipients = $this->service->recipientsForUser($user, 'breach_detected');

    expect(array_keys($recipients))
        ->toContain('sec-a@craftpulse.test')
        ->toContain('sec-b@craftpulse.test');
    expect($recipients)->toHaveCount(2);
});

it('de-duplicates a contact subscribed via two of the user groups', function() {
    seedSubscription((int)$this->groupA->id, 'new_device', 'shared@craftpulse.test');
    seedSubscription((int)$this->groupB->id, 'new_device', 'shared@craftpulse.test');

    $user = userInGroups([(int)$this->groupA->id, (int)$this->groupB->id]);

    $recipients = $this->service->recipientsForUser($user, 'new_device');

    expect($recipients)->toHaveCount(1);
    expect(array_keys($recipients))->toBe(['shared@craftpulse.test']);
});

// =============================================================================
// recipientsForUser — disabled subscription excluded
// =============================================================================

it('excludes a disabled subscription from recipient resolution', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'enabled@craftpulse.test', true);
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'disabled@craftpulse.test', false);

    $user = userInGroups([(int)$this->groupA->id]);

    $recipients = $this->service->recipientsForUser($user, 'breach_detected');

    expect(array_keys($recipients))->toBe(['enabled@craftpulse.test']);
});

// =============================================================================
// recipientsForUser — event-type scoped
// =============================================================================

it('only returns recipients for the requested event type', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'breach@craftpulse.test');
    seedSubscription((int)$this->groupA->id, 'new_device', 'device@craftpulse.test');

    $user = userInGroups([(int)$this->groupA->id]);

    expect(array_keys($this->service->recipientsForUser($user, 'breach_detected')))
        ->toBe(['breach@craftpulse.test']);
    expect(array_keys($this->service->recipientsForUser($user, 'new_device')))
        ->toBe(['device@craftpulse.test']);
});

// =============================================================================
// recipientsForUser — user in no subscribed group → empty
// =============================================================================

it('returns an empty set when the user is in no subscribed group', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'sec-a@craftpulse.test');

    // User is only in group C, which has no subscriptions.
    $user = userInGroups([(int)$this->groupC->id]);

    expect($this->service->recipientsForUser($user, 'breach_detected'))->toBe([]);
});

it('returns an empty set when the user has no groups at all', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'sec-a@craftpulse.test');

    $user = UserFactory::nonAdmin();

    expect($this->service->recipientsForUser($user, 'breach_detected'))->toBe([]);
});

// =============================================================================
// recipientsForUser — resolves from the ACTUAL membership, not a stored global
// =============================================================================

it('reflects a change in the user group membership at resolve time', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'sec-a@craftpulse.test');
    seedSubscription((int)$this->groupB->id, 'breach_detected', 'sec-b@craftpulse.test');

    // Start in A only.
    $user = userInGroups([(int)$this->groupA->id]);
    expect(array_keys($this->service->recipientsForUser($user, 'breach_detected')))
        ->toBe(['sec-a@craftpulse.test']);

    // Move to B only — resolution must follow the new membership.
    Craft::$app->getUsers()->assignUserToGroups($user->id, [(int)$this->groupB->id]);
    $reloaded = \craft\elements\User::find()->id($user->id)->one();

    expect(array_keys($this->service->recipientsForUser($reloaded, 'breach_detected')))
        ->toBe(['sec-b@craftpulse.test']);
});

// =============================================================================
// saveSubscriptions — diff-on-save: keep / insert / delete
// =============================================================================

it('inserts new rows, keeps unchanged rows, and deletes removed rows', function() {
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'keep@craftpulse.test');
    seedSubscription((int)$this->groupA->id, 'breach_detected', 'remove@craftpulse.test');

    $all = $this->service->getAllSubscriptions();
    $keepId = null;
    foreach ($all as $sub) {
        if ($sub->recipientEmail === 'keep@craftpulse.test') {
            $keepId = $sub->id;
        }
    }

    // Submit: keep the keep-row (by its numeric id, unchanged), drop the
    // remove-row (omitted), add a brand-new row.
    $this->service->saveSubscriptions([
        (string)$keepId => [
            'groupId' => (int)$this->groupA->id,
            'eventType' => 'breach_detected',
            'recipientEmail' => 'keep@craftpulse.test',
            'enabled' => true,
        ],
        'new1' => [
            'groupId' => (int)$this->groupB->id,
            'eventType' => 'new_device',
            'recipientEmail' => 'added@craftpulse.test',
            'enabled' => true,
        ],
    ]);

    $emails = array_map(
        static fn($s): string => $s->recipientEmail,
        $this->service->getAllSubscriptions(),
    );

    expect($emails)->toContain('keep@craftpulse.test');
    expect($emails)->toContain('added@craftpulse.test');
    expect($emails)->not->toContain('remove@craftpulse.test');
    expect($this->service->getAllSubscriptions())->toHaveCount(2);
});

it('skips incomplete rows on save', function() {
    $this->service->saveSubscriptions([
        'new1' => [
            'groupId' => (int)$this->groupA->id,
            'eventType' => '',
            'recipientEmail' => 'no-event@craftpulse.test',
            'enabled' => true,
        ],
        'new2' => [
            'groupId' => 0,
            'eventType' => 'breach_detected',
            'recipientEmail' => 'no-group@craftpulse.test',
            'enabled' => true,
        ],
    ]);

    expect($this->service->getAllSubscriptions())->toHaveCount(0);
});
