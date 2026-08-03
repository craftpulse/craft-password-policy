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

use Craft;
use craft\elements\User;
use craft\queue\BaseBatchedJob;
use craftpulse\passwordpolicy\batchers\InactiveAccountBatcher;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\queue\RetryableJobInterface;

/**
 * Class ScanInactiveAccountsJob
 *
 * Batched job that scans for accounts past the configured inactivity
 * threshold (Feature 5, Pro) and applies the configured `inactiveAction`
 * (`report` | `notify` | `suspend`) to each.
 *
 * Pattern: mirrors {@see SendPasswordExpiryRemindersJob}. Each batch's
 * `getSlice()` re-runs the detection query, so a retried batch skips
 * accounts the `suspend` action already handled — the detection query
 * excludes suspended accounts.
 *
 * That shrinking result set is also why pagination is by watermark rather
 * than by offset. {@see InactiveAccountBatcher} carries the full
 * explanation.
 *
 * Per-user soft-fail: a single action failure logs and continues; the batch
 * never bubbles, so one bad user can't poison the rest.
 *
 * Edition gate (queue convention → graceful skip, per
 * `feedback_edition_gate_convention`): on a sub-Pro install the job logs a
 * warning and returns WITHOUT throwing — a throw would surface as a
 * failed-job alert unrelated to operator action. The console command that
 * enqueues this job performs the same Pro check up front and refuses to
 * enqueue, so reaching the in-job gate means an edition downgrade landed
 * between enqueue and run.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 *
 * @property \yii\queue\Queue $queue
 */
class ScanInactiveAccountsJob extends BaseBatchedJob implements RetryableJobInterface
{
    // Public Properties
    // =========================================================================

    /**
     * @var int|null optional threshold override; falls back to the
     *     `inactiveThresholdDays` setting when null
     */
    public ?int $thresholdDays = null;

    /**
     * @var string|null optional action override; falls back to the
     *     `inactiveAction` setting when null
     */
    public ?string $action = null;

    /**
     * The highest user id this campaign has already consumed, carried across
     * the batches `BaseBatchedJob` spawns.
     *
     * Public and serializable on purpose: spawned batches are a `clone` of
     * this job pushed back onto the queue, and `BaseBatchedJob::__sleep()`
     * keeps only public properties. A private cursor would reset to null on
     * every batch and the campaign would restart from the beginning.
     *
     * {@see InactiveAccountBatcher} explains why the campaign needs a
     * watermark at all: under the `suspend` action the detection result set
     * shrinks by exactly what `itemOffset` grows, and under `report` and
     * `notify` it doesn't shrink at all.
     *
     * @var int|null
     *
     * @since 5.2.0
     */
    public ?int $afterId = null;

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

    /**
     * @inheritdoc
     *
     * Pro-gated — graceful skip on sub-Pro installs (queue convention: log
     * + return, never throw). When enabled and Pro, defers to the parent's
     * batched-execute loop.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            PasswordPolicy::$plugin->log(
                'ScanInactiveAccountsJob skipped: inactive-account handling requires the Pro edition.',
            );

            return;
        }

        if (!PasswordPolicy::$plugin->getSettings()->inactiveAccountsEnabled) {
            PasswordPolicy::$plugin->log(
                'ScanInactiveAccountsJob skipped: inactive-account handling is disabled.',
            );

            return;
        }

        parent::execute($queue);
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defaultDescription(): ?string
    {
        return Craft::t('password-policy', 'Scanning for inactive accounts');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function loadData(): InactiveAccountBatcher
    {
        return new InactiveAccountBatcher(
            thresholdDays: $this->_thresholdDays(),
            afterId: $this->afterId,
            processedCount: $this->itemOffset,
        );
    }

    /**
     * @inheritdoc
     *
     * Soft-fail: catch every Throwable so one bad user doesn't poison the
     * batch. The error is logged via the plugin's sensitive-key-stripping
     * logger and processing continues.
     *
     * The campaign watermark advances first, before the action is applied,
     * and for every account handed to this method regardless of outcome. An
     * account left below the watermark would be re-offered by the next batch,
     * which under the non-mutating `report` and `notify` actions means
     * re-offered forever.
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

        $this->afterId = max($this->afterId ?? 0, (int)$item->id);

        try {
            PasswordPolicy::$plugin->getInactiveAccounts()
                ->applyAction($item, $this->_action());
        } catch (Throwable $e) {
            PasswordPolicy::$plugin->log(
                'Failed to action inactive user {userId}: {error}',
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
     * Resolves the action — the override if set, else the setting.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _action(): string
    {
        return $this->action ?? PasswordPolicy::$plugin->getSettings()->inactiveAction;
    }

    /**
     * Resolves the threshold — the override if set, else the setting.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _thresholdDays(): int
    {
        return $this->thresholdDays ?? PasswordPolicy::$plugin->getSettings()->inactiveThresholdDays;
    }
}
