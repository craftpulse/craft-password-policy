<?php
/**
 * Pest coverage for `InactiveAccountBatcher` driven across a MULTI-BATCH
 * campaign, which is the only shape in which its defect was visible.
 *
 * Under the `suspend` action the detection predicate is self-consuming: the
 * query excludes `users.suspended`, so each suspended account leaves the result
 * set, while `craft\queue\BaseBatchedJob` advances `itemOffset` monotonically
 * across the batches it spawns. Paginating that query by offset skips exactly as
 * many accounts as the campaign actioned. With the seven-account fixture and a
 * batch size of three below, the offset-paginated version suspended four of
 * seven and reported clean completion.
 *
 * Under `report` and `notify` the predicate doesn't shrink at all, which is the
 * mirror-image hazard: a slice that ignored the offset without a watermark
 * would hand out the same accounts on every batch and the campaign would never
 * terminate. Both directions are pinned below.
 *
 * A single-batch test cannot see any of that, which is why there was no
 * coverage under `src/batchers/` and why the bug survived.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\helpers\Db;
use craftpulse\passwordpolicy\jobs\ScanInactiveAccountsJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\CapturingQueue;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnabled = $this->settings->inactiveAccountsEnabled;
    $this->originalThreshold = $this->settings->inactiveThresholdDays;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->inactiveAccountsEnabled = true;
    $this->settings->inactiveThresholdDays = 90;

    // The batch-count assertions below need the dormant population to be
    // exactly this test's fixtures. Detection is
    // `COALESCE(lastLoginDate, dateCreated) < cutoff`, so every account that
    // already exists (the bootstrap's seed admin, leftovers from the two
    // non-transactional test cases) would otherwise join the campaign and
    // shift every batch boundary. Stamping a current login makes them
    // ineligible, and the write rolls back with the test transaction.
    Craft::$app->getDb()->createCommand()
        ->update(Table::USERS, ['lastLoginDate' => Db::prepareDateForDb(new DateTime('now'))])
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->inactiveAccountsEnabled = $this->originalEnabled;
    $this->settings->inactiveThresholdDays = $this->originalThreshold;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Creates an account that has been dormant well past the 90-day threshold.
 *
 * `lastLoginDate` is stamped with a direct update: the element save that
 * created the user doesn't take a login date, and detection reads the column
 * rather than the element.
 */
function makeDormantUser(): int
{
    $user = UserFactory::nonAdmin();

    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastLoginDate' => Db::prepareDateForDb(new DateTime('-400 days'))],
            ['id' => $user->id],
        )
        ->execute();

    return (int)$user->id;
}

/**
 * Counts how many of the given accounts are suspended.
 *
 * @param int[] $userIds
 */
function suspendedCount(array $userIds): int
{
    return (int)(new Query())
        ->from(Table::USERS)
        ->where(['id' => $userIds])
        ->andWhere(['suspended' => true])
        ->count();
}

// =============================================================================
// Multi-batch campaign — every dormant account must be actioned
// =============================================================================

it('suspends every dormant account across a campaign that spans several batches', function() {
    $userIds = [];

    for ($i = 0; $i < 7; $i++) {
        $userIds[] = makeDormantUser();
    }

    $batches = CapturingQueue::runCampaign(
        new ScanInactiveAccountsJob(['action' => 'suspend']),
        batchSize: 3,
    );

    // Three batches for seven accounts at three per batch. Two would mean the
    // campaign terminated early, which is precisely how the offset-paginated
    // version failed: its shrinking `count()` fell below the growing offset.
    expect($batches)->toBe(3);

    // The assertion that matters: nothing is left dormant. Under the offset
    // pagination this came back as 4.
    expect(suspendedCount($userIds))->toBe(7);
});

it('suspends every account when the fixture does not divide evenly into batches', function() {
    // The remainder batch is where an off-by-one in the watermark or in the
    // count compensation surfaces.
    $userIds = [];

    for ($i = 0; $i < 10; $i++) {
        $userIds[] = makeDormantUser();
    }

    $batches = CapturingQueue::runCampaign(
        new ScanInactiveAccountsJob(['action' => 'suspend']),
        batchSize: 4,
    );

    expect($batches)->toBe(3)
        ->and(suspendedCount($userIds))->toBe(10);
});

// =============================================================================
// Non-mutating actions — the campaign must still terminate, and reach everyone
// =============================================================================

it('notifies every dormant account exactly once and terminates', function() {
    // `notify` leaves the account matching the detection query, so the result
    // set never shrinks. Without a watermark the campaign would re-offer the
    // same first slice forever; `CapturingQueue::runCampaign()` throws past its
    // batch guard, which is what would fail this test.
    $userIds = [];

    for ($i = 0; $i < 7; $i++) {
        $userIds[] = makeDormantUser();
    }

    $batches = CapturingQueue::runCampaign(
        new ScanInactiveAccountsJob(['action' => 'notify']),
        batchSize: 3,
    );

    expect($batches)->toBe(3)
        ->and(suspendedCount($userIds))->toBe(0);

    foreach ($userIds as $userId) {
        $rows = (new Query())
            ->from('{{%passwordpolicy_notification_log}}')
            ->where(['userId' => $userId, 'notificationType' => 'inactive_account'])
            ->count();

        expect((int)$rows)->toBe(1);
    }
});
