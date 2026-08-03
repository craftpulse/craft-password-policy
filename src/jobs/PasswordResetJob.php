<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\jobs;

use craft\queue\BaseBatchedJob;

use craftpulse\passwordpolicy\batchers\PasswordResetBatcher;
use craftpulse\passwordpolicy\helpers\PasswordResetHelper;
use craftpulse\passwordpolicy\PasswordPolicy;

use Throwable;
use yii\queue\RetryableJobInterface;

/**
 * Class PasswordResetJob
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 *
 * @property \yii\queue\Queue $queue
 */
class PasswordResetJob extends BaseBatchedJob implements RetryableJobInterface
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function init(): void
    {
        parent::init();

        $this->batchSize = 500;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function getTtr(): int
    {
        return 300;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function canRetry($attempt, $error): bool
    {
        return $attempt < 10;
    }

    /**
     * Sets the progress for the current job.
     *
     * @param int $count
     * @param int $total
     * @param string|null $label
     * @return void
     *
     * @author CraftPulse
     */
    public function setProgressHandler(int $count, int $total, ?string $label = null): void
    {
        $progress = $total > 0 ? ($count / $total) : 0;
        $this->setProgress($this->queue, $progress, $label);
    }

    // Protected Methods
    // =========================================================================

    /**
     * Loads the batch data for processing.
     *
     * @return PasswordResetBatcher
     *
     * @author CraftPulse
     */
    protected function loadData(): PasswordResetBatcher
    {
        $users = PasswordResetHelper::getAllUsersToExpire();
        if (empty($users)) {
            return new PasswordResetBatcher([]);
        }

        return new PasswordResetBatcher($users);
    }

    /**
     * Processes a single user item.
     *
     * @param mixed $item
     * @return void
     *
     * @throws Throwable
     *
     * @author CraftPulse
     */
    protected function processItem(mixed $item): void
    {
        PasswordPolicy::$plugin->retention->requirePasswordReset($item);
    }
}
