<?php
/**
 * Pest coverage for `UserIndexService::preloadForUsers()` query batching.
 *
 * Naïve column readers issue O(visibleUsers × columns) queries on the
 * Users index — operator pain point on a CP page rendering hundreds of
 * rows. The preload runs at most three to five small queries (depending
 * on edition) regardless of user count. The contract is asserted via
 * Yii's profiler — count the queries against the relevant plugin tables
 * + `Table::USERS` after the preload run.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getUserIndex();

    $this->originalEdition = $this->plugin->edition;
    // Pin Lite so the resolver branch in preload is skipped — query
    // count for the policy step is intrinsically O(users) and we test
    // it separately under the Pro+ surface.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->service->resetCache();
});

// =============================================================================
// Bounded query count regardless of user count
// =============================================================================

it('runs a bounded set of queries against plugin tables on Lite', function() {
    // Seed 25 users with assorted state.
    $userIds = [];

    for ($i = 0; $i < 25; $i++) {
        $user = UserFactory::admin();
        $userIds[] = $user->id;

        if ($i % 3 === 0) {
            Craft::$app->getDb()->createCommand()
                ->insert('{{%passwordpolicy_password_history}}', [
                    'userId' => $user->id,
                    'passwordHash' => '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012',
                    'changeReason' => 'self_service',
                    'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    'uid' => StringHelper::UUID(),
                ])
                ->execute();
        }

        if ($i % 5 === 0) {
            Craft::$app->getDb()->createCommand()
                ->insert('{{%passwordpolicy_user_state}}', [
                    'userId' => $user->id,
                    'lastBreachCheckAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    'uid' => StringHelper::UUID(),
                ])
                ->execute();
        }
    }

    // Reset the logger buffer so seed-side queries don't leak in. The
    // assertion below cares only about queries the preload itself drove.
    resetQueryLog();

    $countBefore = countPluginQueries();
    $this->service->preloadForUsers($userIds);
    $countAfter = countPluginQueries();

    // Capture for debugging — uncomment if the bound trips on a future
    // Yii release: dump(captureQueries());
    // Lite preload runs three batched SELECTs: users columns, history
    // rows (with self-join subquery — Yii may log the subquery
    // separately, accept up to 6), user_state breach rows. Allow some
    // headroom for framework wrapping queries; the contract is that
    // the count stays bounded regardless of user count, NOT that it
    // scales with N.
    expect($countAfter - $countBefore)
        ->toBeLessThanOrEqual(8)
        ->toBeGreaterThanOrEqual(3);
});

it('treats repeated preload calls with the same IDs as cheap', function() {
    $user = UserFactory::admin();

    $this->service->preloadForUsers([$user->id]);
    $countBefore = countPluginQueries();
    $this->service->preloadForUsers([$user->id]);
    $countAfter = countPluginQueries();

    // Second call hits the in-memory cache short-circuit — zero new queries.
    expect($countAfter - $countBefore)->toBe(0);
});

it('only fetches the new user IDs when called incrementally', function() {
    $first = UserFactory::admin();
    $second = UserFactory::admin();

    $this->service->preloadForUsers([$first->id]);
    resetQueryLog();
    $countBefore = countPluginQueries();

    // Pass both IDs — only the second should drive new queries.
    $this->service->preloadForUsers([$first->id, $second->id]);
    $countAfter = countPluginQueries();

    expect($countAfter - $countBefore)
        ->toBeLessThanOrEqual(8)
        ->toBeGreaterThanOrEqual(3);
});

it('handles an empty user-id list without querying', function() {
    $countBefore = countPluginQueries();
    $this->service->preloadForUsers([]);
    $countAfter = countPluginQueries();

    expect($countAfter - $countBefore)->toBe(0);
});

it('does not scale query count with user count', function() {
    // Two preloads — one for a single user, one for ten — both should
    // run the same constant number of plugin SELECTs. Different
    // service instances so per-service cache doesn't perturb the count.
    $singleService = new \craftpulse\passwordpolicy\services\UserIndexService();
    $batchService = new \craftpulse\passwordpolicy\services\UserIndexService();

    $singleUser = UserFactory::admin();
    $batchUsers = array_map(fn() => UserFactory::admin()->id, range(1, 10));

    resetQueryLog();
    $beforeSingle = countPluginQueries();
    $singleService->preloadForUsers([$singleUser->id]);
    $afterSingle = countPluginQueries();

    resetQueryLog();
    $beforeBatch = countPluginQueries();
    $batchService->preloadForUsers($batchUsers);
    $afterBatch = countPluginQueries();

    // The two preloads should issue the same query count regardless
    // of how many user IDs they were handed.
    expect($afterBatch - $beforeBatch)->toBe($afterSingle - $beforeSingle);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Clears the Yii logger buffer so subsequent `countPluginQueries()`
 * calls only see queries driven by the code under test.
 */
function resetQueryLog(): void
{
    /** @var \yii\log\Logger $logger */
    $logger = Craft::getLogger();
    $logger->messages = [];
}

/**
 * Counts SELECT queries against the plugin's preload-relevant tables.
 * Filters on `yii\db\` category messages so the count is grounded in
 * actual command execution, then narrows to messages mentioning the
 * tables the preload reads. Anything else (Craft internals,
 * site/element resolution, etc.) doesn't pollute the assertion.
 */
function countPluginQueries(): int
{
    /** @var \yii\log\Logger $logger */
    $logger = Craft::getLogger();

    $count = 0;
    $usersTable = Table::USERS;

    foreach ($logger->messages as $entry) {
        // Yii log entries are [message, level, category, timestamp, traces]
        $msg = $entry[0] ?? null;
        $category = $entry[2] ?? null;

        if (!is_string($msg) || !is_string($category)) {
            continue;
        }

        if (!str_starts_with($category, 'yii\\db\\')) {
            continue;
        }

        // Only count SELECTs initiated by the preload.
        if (!str_contains($msg, 'SELECT')) {
            continue;
        }

        if (
            str_contains($msg, 'passwordpolicy_password_history')
            || str_contains($msg, 'passwordpolicy_user_state')
            || preg_match('/\bFROM `?' . preg_quote($usersTable, '/') . '`?/', $msg)
        ) {
            $count++;
        }
    }

    return $count;
}
