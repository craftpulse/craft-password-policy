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
 * Recomputes the pending-recipients query each `getSlice()` call rather
 * than caching the user list at construction time. That gives natural
 * idempotency on retry — if a batch partially completes (some users
 * notified, log rows written) and the job is retried, the next slice
 * re-queries and skips the already-notified users.
 *
 * Same shape as putenv/Campaign uses for batched contact resolution.
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
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        private readonly ?int $userId = null,
    ) {
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function count(): int
    {
        return $this->_buildQuery()->count();
    }

    /**
     * @inheritdoc
     *
     * Returns User elements rather than rows so the job can call into the
     * notification service with the full user model.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        $userIds = $this->_buildQuery()
            ->offset($offset)
            ->limit($limit)
            ->orderBy(['users.id' => SORT_ASC])
            ->column();

        if (empty($userIds)) {
            return [];
        }

        return User::find()
            ->id($userIds)
            ->status(null)
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
