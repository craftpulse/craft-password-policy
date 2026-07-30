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

use Craft;
use craft\helpers\Queue;
use craft\queue\BaseJob;
use craftpulse\auditkit\errors\ChainWriteRetriesExhaustedException;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;

/**
 * Class WriteAuditChainEntryJob
 *
 * The deferred recovery path {@see \craftpulse\passwordpolicy\services\AuditLogService::logEvent()}
 * hands a failed inline chain write to. It carries the fully-resolved event
 * data captured at request time (geo lookup, HMAC hashing already done) and
 * retries the write through {@see \craftpulse\passwordpolicy\services\AuditLogService::writePrepared()}.
 *
 * Chain ordering stays correct regardless of when the retry lands: the
 * `SELECT ... FOR UPDATE` tail read inside the kit
 * {@see \craftpulse\auditkit\engine\ChainWriter} serializes every writer, so
 * a retried write and any inline write racing it cannot fork the chain.
 *
 * Never silently drops. A write that still fails here is logged at error
 * level with the full event payload and requeued with a jittered backoff
 * delay, up to {@see MAX_REQUEUE_ATTEMPTS} times, before the event is
 * finally given up on, loudly, with the last attempt's failure in the log.
 * This is on top of {@see \craftpulse\auditkit\engine\ChainWriter}'s own
 * bounded in-transaction retry against transient lock contention; this
 * job's requeue is the outer layer for whatever ChainWriter's own retry
 * budget couldn't absorb.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WriteAuditChainEntryJob extends BaseJob
{
    // Const Properties
    // =========================================================================

    /**
     * @var int The number of times this job requeues itself against a
     *     persistent chain-write failure before giving up.
     */
    public const MAX_REQUEUE_ATTEMPTS = 3;

    /**
     * @var int The backoff floor, in seconds, before jitter is applied to a
     *     requeue delay.
     */
    private const BASE_BACKOFF_SECONDS = 5;

    // Public Properties
    // =========================================================================

    /**
     * @var array<string, mixed> The prepared entry data, with all
     *     request/actor context already resolved at capture time by
     *     {@see \craftpulse\passwordpolicy\services\AuditLogService::logEvent()}.
     */
    public array $data = [];

    /**
     * @var int The number of times this specific event has already been
     *     requeued after a chain-write failure. Zero on the first attempt;
     *     incremented on every requeue so {@see MAX_REQUEUE_ATTEMPTS} is
     *     enforced across the retry chain, not just a single job run.
     */
    public int $requeueAttempt = 0;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @param \yii\queue\Queue $queue
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        try {
            PasswordPolicy::$plugin->getAuditLog()->writePrepared($this->data);
        } catch (Throwable $e) {
            $this->_handleFailure($e);
        }
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defaultDescription(): ?string
    {
        return Craft::t('password-policy', 'Writing deferred audit log entry');
    }

    // Private Methods
    // =========================================================================

    /**
     * Handles a chain-write failure: logs it at error level with the full
     * event payload — distinguishing a {@see ChainWriteRetriesExhaustedException}
     * (ChainWriter's own retry budget exhausted) from any other throwable in
     * the message — then requeues with a jittered backoff delay, unless
     * this event's requeue budget is already exhausted, in which case the
     * loss is logged loudly and final.
     *
     * @param Throwable $e
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _handleFailure(Throwable $e): void
    {
        $reason = $e instanceof ChainWriteRetriesExhaustedException
            ? sprintf('ChainWriter exhausted its own %d-attempt retry budget', $e->attempts)
            : $e->getMessage();

        if ($this->requeueAttempt >= self::MAX_REQUEUE_ATTEMPTS) {
            Craft::error(
                sprintf(
                    'Audit log chain write permanently failed for event "%s" after %d requeue attempt(s): %s. Payload: %s',
                    $this->data['event'] ?? 'unknown',
                    $this->requeueAttempt,
                    $reason,
                    json_encode($this->data),
                ),
                'password-policy',
            );

            return;
        }

        $nextAttempt = $this->requeueAttempt + 1;

        Craft::error(
            sprintf(
                'Audit log deferred chain write failed for event "%s", requeue attempt %d of %d: %s. Payload: %s',
                $this->data['event'] ?? 'unknown',
                $nextAttempt,
                self::MAX_REQUEUE_ATTEMPTS,
                $reason,
                json_encode($this->data),
            ),
            'password-policy',
        );

        Queue::push(
            new self([
                'data' => $this->data,
                'requeueAttempt' => $nextAttempt,
            ]),
            delay: self::_backoffSeconds($nextAttempt),
        );
    }

    /**
     * Computes a full-jitter exponential backoff delay, in seconds, for the
     * given (1-indexed) requeue attempt.
     *
     * @param int $attempt
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _backoffSeconds(int $attempt): int
    {
        $exponential = self::BASE_BACKOFF_SECONDS * (2 ** ($attempt - 1));

        return random_int(0, $exponential);
    }
}
