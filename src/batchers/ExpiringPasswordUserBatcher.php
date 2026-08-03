<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\batchers;

use Carbon\Carbon;
use craft\base\Batchable;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class ExpiringPasswordUserBatcher
 *
 * Batchable for users whose passwords expire within the configured
 * `expiryReminderDays` window AND have no `notification_log` row for
 * `(userId, type='expiry_reminder')` within the dedup window.
 *
 * ## Why this paginates by watermark and not by offset
 *
 * The pending-recipients predicate is SELF-CONSUMING: sending a reminder
 * writes a `notification_log` row, which the `NOT EXISTS` subquery below
 * then excludes, so every notified user leaves the result set.
 * `craft\queue\BaseBatchedJob` meanwhile advances `itemOffset`
 * monotonically across the batches it spawns. An offset-paginated
 * `getSlice()` therefore skips exactly as many users as it notified: with
 * a batch size of 100 and 250 eligible users, the second batch asks for
 * rows 101-200 of a result set that now holds 150, and the job reports
 * clean completion having emailed roughly half of them. Users silently not
 * warned before their password expires is the whole point of the feature,
 * so this is not a tolerable rounding error.
 *
 * The fix is the watermark pattern already used by
 * {@see \craftpulse\passwordpolicy\jobs\WebhookForwardJob::processItem()}:
 * pagination is keyed on the last id the campaign consumed rather than on
 * a row count. Two constructor arguments carry the campaign's position,
 * both fed from public properties on the job so they survive the
 * `clone` + serialize that spawns the next batch:
 *
 *  - `$afterId` bounds the slice to `users.id > $afterId`, so `$offset` is
 *    ignored entirely and no user is ever handed out twice.
 *  - `$processedCount` is added back into `count()`, because
 *    `BaseBatchedJob` terminates on `itemOffset < totalItems()` and a
 *    shrinking total would strand the tail of the campaign.
 *
 * A user whose send fails writes no log row and sits BELOW the watermark,
 * so they are skipped for the rest of the campaign and picked up by the
 * next scheduled run (which starts from a null watermark). That is
 * deliberate: re-offering a permanently failing recipient inside the same
 * campaign would grow `count()` on every batch and the job would never
 * terminate.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ExpiringPasswordUserBatcher implements Batchable
{
    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param int|null $userId optional single-user mode (for `--user=<id>`)
     * @param int|null $afterId the highest user id the campaign has already
     *     consumed; null starts a fresh campaign
     * @param int $processedCount how many users earlier batches of this
     *     campaign already consumed, added back into {@see self::count()}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        private readonly ?int $userId = null,
        private readonly ?int $afterId = null,
        private readonly int $processedCount = 0,
    ) {
    }

    /**
     * @inheritdoc
     *
     * Users this campaign already consumed plus the recipients still
     * pending past the watermark. The offset `BaseBatchedJob` compares
     * against is cumulative across batches, so a bare remaining-rows count
     * would fall below it and end the campaign early.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function count(): int
    {
        return $this->processedCount + $this->_buildQuery()->count();
    }

    /**
     * @inheritdoc
     *
     * Returns User elements rather than rows so the job can call into the
     * notification service with the full user model.
     *
     * `$offset` is deliberately unused: the slice is bounded by the
     * campaign's watermark instead. See the class docblock.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        $userIds = $this->_buildQuery()
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
     * Builds the pending-recipients query. Selects user IDs only — slice
     * resolves them to User elements via UserQuery so the active-status
     * scope is honoured.
     *
     * @return Query
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildQuery(): Query
    {
        $settings = PasswordPolicy::$plugin->getSettings();
        $reminderDays = max(1, $settings->expiryReminderDays);
        $dedupDays = max(1, $settings->expiryReminderDays);

        $expiryThreshold = $this->_expiryThreshold($settings->expiryAmount, $settings->expiryPeriod);
        $reminderWindowEnd = Carbon::now('UTC')->subDays(
            max(0, $expiryThreshold - $reminderDays),
        )->format('Y-m-d H:i:s');

        $dedupWindow = Carbon::now('UTC')->subDays($dedupDays)->format('Y-m-d H:i:s');

        $query = (new Query())
            ->select(['users.id'])
            ->from(['users' => Table::USERS])
            ->where(['users.suspended' => false])
            ->andWhere(['users.locked' => false])
            ->andWhere(['users.pending' => false])
            ->andWhere(['not', ['users.lastPasswordChangeDate' => null]])
            ->andWhere(['<', 'users.lastPasswordChangeDate', $reminderWindowEnd])
            ->andWhere(['not exists', (new Query())
                ->from(['nl' => '{{%passwordpolicy_notification_log}}'])
                ->where('[[nl.userId]] = [[users.id]]')
                ->andWhere(['nl.notificationType' => 'expiry_reminder'])
                ->andWhere(['>=', 'nl.sentAt', $dedupWindow]),
            ]);

        if ($this->userId !== null) {
            $query->andWhere(['users.id' => $this->userId]);
        }

        if ($this->afterId !== null) {
            $query->andWhere(['>', 'users.id', $this->afterId]);
        }

        return $query;
    }

    /**
     * Returns the absolute expiry-age threshold in days.
     *
     * Mirrors `PasswordResetHelper::_createInterval` arithmetic — converts
     * the (amount, period) pair into a single day count for the
     * lastPasswordChangeDate comparison.
     *
     * @param int|null $amount
     * @param string|null $period
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _expiryThreshold(?int $amount, ?string $period): int
    {
        if ($amount === null || $amount <= 0 || $period === null) {
            return 0;
        }

        return match ($period) {
            'day' => $amount,
            'week' => $amount * 7,
            'month' => $amount * 30,
            'year' => $amount * 365,
            default => 0,
        };
    }
}
