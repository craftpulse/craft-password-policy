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

use craft\queue\BaseBatchedJob;

use craftpulse\passwordpolicy\batchers\PasswordResetBatcher;
use craftpulse\passwordpolicy\helpers\PasswordResetHelper;
use craftpulse\passwordpolicy\PasswordPolicy;

use yii\queue\Queue;
use yii\queue\RetryableJobInterface;

/**
 * Class PasswordResetJob
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 *
 * @property Queue $queue
 */
class PasswordResetJob extends BaseBatchedJob implements RetryableJobInterface
{
    /**
     * @var array
     */
    public array $users;

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();

        // @TODO create JobBatchSize setting
        $this->batchSize = 500;
    }

    /**
     * @inheritdoc
     */
    public function getTtr(): int
    {
        return 300;
    }

    /**
     * @inheritdoc
     */
    public function canRetry($attempt, $error): bool
    {
        // @TODO create maxRetryAttempts;
        return $attempt < 10;
    }

    /**
     * Handles setting the progress.
     */
    public function setProgressHandler(int $count, int $total, string $label = null): void
    {
        $progress = $total > 0 ? ($count / $total) : 0;
        $this->setProgress($this->queue, $progress, $label);
    }

    protected function loadData(): PasswordResetBatcher
    {
        $users = PasswordResetHelper::getAllUsersToExpire();
        if (!empty($users)) {
            return new PasswordResetBatcher([]);
        }

        return new PasswordResetBatcher($users);
    }

    /**
     * @inheritdoc
     */
    protected function processItem(mixed $item): void
    {
        PasswordPolicy::$plugin->retention->requirePasswordReset($item);
    }
}
