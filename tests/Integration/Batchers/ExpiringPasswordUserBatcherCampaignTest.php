<?php
/**
 * Pest coverage for `ExpiringPasswordUserBatcher` driven across a MULTI-BATCH
 * campaign, which is the only shape in which its defect was visible.
 *
 * The pending-recipients predicate is self-consuming: dispatching a reminder
 * writes a `notification_log` row, which the batcher's `NOT EXISTS` subquery
 * then excludes, so each notified user leaves the result set, while
 * `craft\queue\BaseBatchedJob` advances `itemOffset` monotonically across the
 * batches it spawns. Paginating that query by offset skips exactly as many
 * users as the campaign notified. With the seven-user fixture and a batch size
 * of three below, the offset-paginated version emailed four of seven and
 * reported clean completion.
 *
 * A single-batch test cannot see any of that, which is why there was no
 * coverage under `src/batchers/` and why the bug survived.
 *
 * The assertion is on `notification_log` rows rather than on delivered mail:
 * `NotificationService` writes a row for every dispatch attempt, sent or
 * failed, and it is that row that removes the user from the batcher's
 * predicate. Whether the transport succeeded is `NotificationService`'s
 * contract, pinned elsewhere.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\helpers\Db;
use craftpulse\passwordpolicy\jobs\SendPasswordExpiryRemindersJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\CapturingQueue;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\MailerFixture;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;
    $this->originalReminderDays = $this->settings->expiryReminderDays;

    // 90-day expiry, reminders 7 days out: any user whose password last
    // changed more than 83 days ago is a pending recipient.
    $this->settings->expiryAmount = 90;
    $this->settings->expiryPeriod = 'day';
    $this->settings->expiryReminderDays = 7;

    MailerFixture::pin();

    // The dedup gate is cache-and-table backed, so a fire recorded by an
    // earlier file would suppress this campaign's dispatches and no
    // notification_log row would be written.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_alert_cooldowns}}')
        ->execute();
    Craft::$app->getCache()->flush();

    // The batch-count assertions below need the eligible population to be
    // exactly this test's fixtures. Any account already carrying an old
    // `lastPasswordChangeDate` (the bootstrap's seed admin, or leftovers from
    // the two non-transactional test cases) would otherwise join the campaign
    // and shift every batch boundary. Clearing the column is what makes an
    // account ineligible, and the write rolls back with the test transaction.
    Craft::$app->getDb()->createCommand()
        ->update(Table::USERS, ['lastPasswordChangeDate' => null])
        ->execute();
});

afterEach(function() {
    MailerFixture::restore();

    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
    $this->settings->expiryReminderDays = $this->originalReminderDays;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Creates a user whose password is old enough to be inside the reminder window.
 *
 * `lastPasswordChangeDate` is stamped with a direct update because
 * `craft\elements\db\UserQuery` doesn't select the column, so it can't be
 * round-tripped through the element, and the plugin's own save listeners would
 * otherwise reset it to now.
 */
function makeExpiringUser(): int
{
    $user = UserFactory::nonAdmin();

    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => Db::prepareDateForDb(new DateTime('-120 days'))],
            ['id' => $user->id],
        )
        ->execute();

    return (int)$user->id;
}

/**
 * Counts `expiry_reminder` notification rows for the given users.
 *
 * @param int[] $userIds
 */
function expiryReminderRowCount(array $userIds): int
{
    return (int)(new Query())
        ->from('{{%passwordpolicy_notification_log}}')
        ->where(['notificationType' => 'expiry_reminder'])
        ->andWhere(['userId' => $userIds])
        ->count();
}

// =============================================================================
// Multi-batch campaign — every eligible recipient must be reached
// =============================================================================

it('reminds every pending recipient across a campaign that spans several batches', function() {
    $userIds = [];

    for ($i = 0; $i < 7; $i++) {
        $userIds[] = makeExpiringUser();
    }

    $batches = CapturingQueue::runCampaign(new SendPasswordExpiryRemindersJob(), batchSize: 3);

    // Three batches for seven recipients at three per batch. Two would mean
    // the campaign terminated early, which is precisely how the
    // offset-paginated version failed.
    expect($batches)->toBe(3);

    // The assertion that matters: nobody was skipped. Under the offset
    // pagination this came back as 4.
    expect(expiryReminderRowCount($userIds))->toBe(7);
});

it('reminds every recipient when the fixture does not divide evenly into batches', function() {
    // The remainder batch is where an off-by-one in the watermark or in the
    // count compensation surfaces.
    $userIds = [];

    for ($i = 0; $i < 10; $i++) {
        $userIds[] = makeExpiringUser();
    }

    $batches = CapturingQueue::runCampaign(new SendPasswordExpiryRemindersJob(), batchSize: 4);

    expect($batches)->toBe(3)
        ->and(expiryReminderRowCount($userIds))->toBe(10);
});

it('writes exactly one reminder row per recipient', function() {
    // A watermark that failed to advance would re-offer an already-notified
    // user. The service's own dedup gate would swallow the second dispatch,
    // so the duplicate would be invisible in the row count: the batch count
    // is what exposes it.
    $userIds = [];

    for ($i = 0; $i < 6; $i++) {
        $userIds[] = makeExpiringUser();
    }

    $batches = CapturingQueue::runCampaign(new SendPasswordExpiryRemindersJob(), batchSize: 2);

    expect($batches)->toBe(3)
        ->and(expiryReminderRowCount($userIds))->toBe(6);

    foreach ($userIds as $userId) {
        expect(expiryReminderRowCount([$userId]))->toBe(1);
    }
});
