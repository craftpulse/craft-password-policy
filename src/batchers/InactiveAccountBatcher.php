<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\batchers;

use craft\base\Batchable;
use craft\db\Query;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class InactiveAccountBatcher
 *
 * Batchable over the inactive-account detection query (Feature 5, Pro).
 * Delegates to {@see \craftpulse\passwordpolicy\services\InactiveAccountService::findInactiveUsers()}
 * so the detection logic has a single source of truth shared with the CP
 * report surface — no duplicated WHERE clauses to drift apart.
 *
 * ## Why this paginates by watermark and not by offset
 *
 * The detection predicate is SELF-CONSUMING under the `suspend` action:
 * the query excludes `users.suspended`, so every account the job suspends
 * leaves the result set. `craft\queue\BaseBatchedJob` meanwhile advances
 * `itemOffset` monotonically across the batches it spawns. An
 * offset-paginated `getSlice()` therefore skips exactly as many accounts as
 * it actioned: with a batch size of 100 and 250 dormant accounts, the
 * second batch asks for rows 101-200 of a result set that now holds 150,
 * and the job reports clean completion having actioned roughly half of
 * them. Dormant accounts silently left open is exactly the exposure the
 * feature exists to close, so this is not a tolerable rounding error.
 *
 * The fix is the watermark pattern already used by
 * {@see \craftpulse\passwordpolicy\jobs\WebhookForwardJob::processItem()}:
 * pagination is keyed on the last id the campaign consumed rather than on
 * a row count. Two constructor arguments carry the campaign's position,
 * both fed from public properties on the job so they survive the
 * `clone` + serialize that spawns the next batch:
 *
 *  - `$afterId` bounds the slice to `users.id > $afterId`, so `$offset` is
 *    ignored entirely and no account is ever handed out twice.
 *  - `$processedCount` is added back into `count()`, because
 *    `BaseBatchedJob` terminates on `itemOffset < totalItems()` and a
 *    shrinking total would strand the tail of the campaign.
 *
 * The watermark is also what makes the non-consuming actions correct. Under
 * `report` and `notify` nothing about the account changes, so the predicate
 * matches it again on the next batch; without a watermark the campaign
 * would re-hand-out the same first N accounts forever, since `count()`
 * would never shrink.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class InactiveAccountBatcher implements Batchable
{
    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param int $thresholdDays days of inactivity before an account counts
     *     as inactive
     * @param int|null $afterId the highest user id the campaign has already
     *     consumed; null starts a fresh campaign
     * @param int $processedCount how many accounts earlier batches of this
     *     campaign already consumed, added back into {@see self::count()}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        private readonly int $thresholdDays,
        private readonly ?int $afterId = null,
        private readonly int $processedCount = 0,
    ) {
    }

    /**
     * @inheritdoc
     *
     * Accounts this campaign already consumed plus the accounts still
     * pending past the watermark. The offset `BaseBatchedJob` compares
     * against is cumulative across batches, so a bare remaining-rows count
     * would fall below it and end the campaign early.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function count(): int
    {
        return $this->processedCount + $this->_query()->count();
    }

    /**
     * @inheritdoc
     *
     * Returns User elements rather than rows so the job can call into the
     * inactive-account service with the full user model.
     *
     * `$offset` is deliberately unused: the slice is bounded by the
     * campaign's watermark instead. See the class docblock.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        $userIds = $this->_query()
            ->limit($limit)
            ->orderBy(['users.id' => SORT_ASC])
            ->column();

        if (empty($userIds)) {
            return [];
        }

        // Ascending id order matters: the job advances its watermark per
        // processed item, and `BaseBatchedJob::execute()` can break out of a
        // slice early under memory or TTR pressure. Handing items out in id
        // order means whatever it didn't reach still sits above the watermark.
        return User::find()
            ->id($userIds)
            ->status(null)
            ->orderBy(['users.id' => SORT_ASC])
            ->all();
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the shared detection query from the service, bounded by the
     * campaign's watermark.
     *
     * @return Query
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _query(): Query
    {
        $query = PasswordPolicy::$plugin->getInactiveAccounts()
            ->findInactiveUsers($this->thresholdDays);

        if ($this->afterId !== null) {
            $query->andWhere(['>', 'users.id', $this->afterId]);
        }

        return $query;
    }
}
