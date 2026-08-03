<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craft\queue\BaseBatchedJob;
use RuntimeException;
use yii\queue\Queue as BaseQueue;

/**
 * Queue stub that captures pushed jobs in memory instead of writing them to
 * the `queue` table.
 *
 * Exists for the batched-job campaign tests. `craft\queue\BaseBatchedJob`
 * processes exactly one slice per `execute()` call and then pushes a `clone` of
 * itself for the next slice, so a test that only calls `execute()` once
 * exercises a single batch and can never observe the offset-versus-predicate
 * drift that made the batchers skip half their work. Driving the whole campaign
 * needs the spawned job back.
 *
 * The capture happens at `pushMessage()`, BELOW `yii\queue\Queue::push()`'s
 * serializer call, so what comes back out has been through a real
 * `serialize()` / `unserialize()` round trip. That is the point rather than an
 * accident: `BaseBatchedJob::__sleep()` keeps only public properties, so a
 * campaign cursor held in a private property would silently reset on every
 * batch, and a stub that passed the live object through would hide it.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class CapturingQueue extends BaseQueue
{
    // Public Properties
    // =========================================================================

    /**
     * Jobs pushed to this queue, in push order, each unserialized from the
     * message the real serializer produced.
     *
     * @var object[]
     *
     * @since 5.2.0
     */
    public array $pushed = [];

    // Public Methods
    // =========================================================================

    /**
     * Runs a batched job to completion, feeding each spawned batch back in the
     * way a queue worker would, and returns how many batches it took.
     *
     * @param BaseBatchedJob $job the first batch of the campaign
     * @param int $batchSize items per slice; set small so a test fixture spans
     *     several batches without needing hundreds of rows
     * @param int $maxBatches abort guard, so a campaign that fails to
     *     terminate fails the test instead of hanging the suite
     * @return int the number of batches executed
     *
     * @throws RuntimeException if the campaign hasn't finished within
     *     `$maxBatches` batches.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function runCampaign(BaseBatchedJob $job, int $batchSize, int $maxBatches = 25): int
    {
        $queue = new self();
        $current = $job;
        $batches = 0;

        while ($current !== null) {
            if ($batches >= $maxBatches) {
                throw new RuntimeException(sprintf(
                    'Batched campaign did not terminate within %d batches.',
                    $maxBatches,
                ));
            }

            $current->batchSize = $batchSize;
            $queue->pushed = [];
            $current->execute($queue);
            $batches++;

            $next = array_shift($queue->pushed);
            $current = $next instanceof BaseBatchedJob ? $next : null;
        }

        return $batches;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function status($id): int
    {
        return self::STATUS_WAITING;
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function pushMessage($message, $ttr, $delay, $priority): string
    {
        $this->pushed[] = $this->serializer->unserialize($message);

        return (string)count($this->pushed);
    }
}
