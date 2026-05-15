<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\jobs;

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\queue\BaseBatchedJob;
use craftpulse\passwordpolicy\batchers\ExpiringPasswordUserBatcher;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\queue\RetryableJobInterface;

/**
 * Class SendPasswordExpiryRemindersJob
 *
 * Batched job that sends password-expiry reminders to every user
 * whose `lastPasswordChangeDate` puts them inside the
 * `expiryReminderDays` window AND who hasn't received a reminder in
 * the dedup window. Universal across editions since 5.2.0 — Lite
 * renders the seeded `expiry-reminder` template, Pro renders whatever
 * the Notification Templates editor wrote.
 *
 * Pattern: Campaign-style. Each batch's `getSlice()` re-runs the
 * pending-recipients query, so retries are naturally idempotent —
 * already-notified users drop out via the `notification_log` exclusion
 * subquery.
 *
 * Per-user soft-fail: a single send failure logs and continues; the
 * batch never bubbles, so one bad user can't poison the rest.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 *
 * @property \yii\queue\Queue $queue
 */
class SendPasswordExpiryRemindersJob extends BaseBatchedJob implements RetryableJobInterface
{
    // Public Properties
    // =========================================================================

    /**
     * @var int|null optional single-user mode for `--user=<id>` invocations
     */
    public ?int $userId = null;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function init(): void
    {
        parent::init();
        $this->batchSize = 100;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTtr(): int
    {
        return 300;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canRetry($attempt, $error): bool
    {
        return $attempt < 5;
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Universal across editions since 5.2.0. The job renders against
     * the seeded `expiry-reminder` template — Lite operators get the
     * default copy, Pro operators get whatever the Notification
     * Templates editor wrote.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        parent::execute($queue);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defaultDescription(): ?string
    {
        return $this->userId !== null
            ? Craft::t('password-policy', 'Sending password expiry reminder to user {id}', ['id' => $this->userId])
            : Craft::t('password-policy', 'Sending password expiry reminders');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function loadData(): ExpiringPasswordUserBatcher
    {
        return new ExpiringPasswordUserBatcher($this->userId);
    }

    /**
     * @inheritdoc
     *
     * Soft-fail: catch every Throwable so one bad user doesn't poison the
     * batch. The error is logged via the plugin's sensitive-key-stripping
     * logger and processing continues.
     *
     * @param User $item
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function processItem(mixed $item): void
    {
        if (!$item instanceof User) {
            return;
        }

        try {
            $daysRemaining = $this->_daysRemaining($item);

            if ($daysRemaining === null) {
                return;
            }

            PasswordPolicy::$plugin->getNotification()
                ->sendPasswordExpiryReminder($item, $daysRemaining);
        } catch (Throwable $e) {
            PasswordPolicy::$plugin->log(
                'Failed to send expiry reminder to user {userId}: {error}',
                [
                    'userId' => $item->id,
                    'error' => $e->getMessage(),
                ],
            );
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Computes how many days until the user's password expires.
     *
     * Returns null when the global expiry settings aren't configured
     * (no expiry → no reminder), or when the user has no
     * lastPasswordChangeDate (e.g. legacy account never seeded).
     *
     * @param User $user
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _daysRemaining(User $user): ?int
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $totalDays = match ($settings->expiryPeriod) {
            'day' => $settings->expiryAmount,
            'week' => $settings->expiryAmount * 7,
            'month' => $settings->expiryAmount * 30,
            'year' => $settings->expiryAmount * 365,
            default => 0,
        };

        if ($totalDays <= 0) {
            return null;
        }

        $lastChange = $this->_lastPasswordChangeDate($user->id);
        if ($lastChange === null) {
            return null;
        }

        $expiresAt = Carbon::instance($lastChange)->addDays($totalDays);
        $remaining = (int)Carbon::now('UTC')->diffInDays($expiresAt, false);

        return max(0, $remaining);
    }

    /**
     * Loads the user's lastPasswordChangeDate via direct DB query.
     *
     * `UserQuery::beforePrepare()` doesn't select this column, so the
     * User element comes back with `lastPasswordChangeDate = null` even
     * when the DB has the value. Same workaround as
     * `PasswordPolicyVariable::lastPasswordChange()`.
     *
     * @param int $userId
     * @return \DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _lastPasswordChangeDate(int $userId): ?\DateTime
    {
        $value = (new Query())
            ->select(['lastPasswordChangeDate'])
            ->from(Table::USERS)
            ->where(['id' => $userId])
            ->scalar();

        if ($value === false || $value === null) {
            return null;
        }

        try {
            return new \DateTime((string)$value, new \DateTimeZone('UTC'));
        } catch (\Throwable) {
            return null;
        }
    }
}
