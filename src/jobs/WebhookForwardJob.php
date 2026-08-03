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

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\queue\BaseBatchedJob;
use craftpulse\passwordpolicy\batchers\WebhookEndpointBatcher;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\queue\RetryableJobInterface;

/**
 * Class WebhookForwardJob
 *
 * Enterprise-only batched job that dispatches audit-log rows to every
 * active webhook endpoint as an INDEPENDENT subscriber. Endpoint A's
 * success does NOT mark endpoint B's row delivered — each endpoint
 * tracks its own dispatch cursor via the
 * `passwordpolicy_webhook_endpoints.lastDeliveredRowId` column.
 *
 * Outer loop: endpoints (batched by this job).
 * Inner loop: audit rows past each endpoint's watermark (bounded per
 * `processItem` to keep TTR-friendly even on endpoints with deep
 * backlogs).
 *
 * Per-endpoint failure isolation: when a dispatch to endpoint A fails,
 * its inner loop stops (don't keep banging on a dead endpoint inside
 * one processItem call), `consecutiveFailures` increments, and the
 * cursor stays put. The next job invocation retries that endpoint
 * starting from the same cursor. Endpoint B's processing in the same
 * batch is unaffected.
 *
 * Edition gate: the job exits early when the plugin is not running
 * Enterprise. Mirror of G8's pattern — the queue job can outlive an
 * edition downgrade (someone removes the Enterprise license, the
 * plugin drops to Pro, but a previously-enqueued forward job sits in
 * the queue). Crashing every retry compounds noise; silent exit + log
 * line is the right cost.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 *
 * @property \yii\queue\Queue $queue
 */
class WebhookForwardJob extends BaseBatchedJob implements RetryableJobInterface
{
    // Const Properties
    // =========================================================================

    /**
     * Maximum audit rows dispatched per endpoint within a single
     * `processItem` call. Bounds the per-endpoint runtime so an
     * endpoint with a deep backlog doesn't blow past TTR. The
     * remainder gets picked up on the next job invocation.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const MAX_ROWS_PER_ENDPOINT = 100;

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
        $this->batchSize = 10;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTtr(): int
    {
        return 600;
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
     * Edition gate at the very top. A queue picker that finds this job
     * on a Lite or Pro install (post-downgrade scenario) exits silently
     * after logging a warning. Crashing the job on every retry would
     * compound noise without recovering anything.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            Craft::warning(
                'WebhookForwardJob skipped: webhook delivery requires the Enterprise edition.',
                'password-policy',
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
        return Craft::t('password-policy', 'Dispatching audit events to webhook endpoints');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function loadData(): WebhookEndpointBatcher
    {
        return new WebhookEndpointBatcher();
    }

    /**
     * @inheritdoc
     *
     * Processes one endpoint per call. Fetches up to
     * {@see MAX_ROWS_PER_ENDPOINT} audit rows past the endpoint's
     * watermark, filters by the endpoint's allowlist, and dispatches
     * in id-order.
     *
     * Success: bump cursor, reset `consecutiveFailures` (handled by
     * the service's circuit logic).
     *
     * Failure: stop the inner loop, increment `consecutiveFailures`
     * (handled by the service), leave the cursor where it was so the
     * next job retries the same row. The service trips the circuit at
     * threshold; the next batch's `getActiveEndpoints()` query
     * excludes it inside the cooldown.
     *
     * @param mixed $item the WebhookEndpointModel
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function processItem(mixed $item): void
    {
        if (!$item instanceof WebhookEndpointModel || $item->id === null) {
            return;
        }

        $service = PasswordPolicy::$plugin->getWebhook();
        $eligible = $service->getEligibleEventClasses($item);
        $eligibleStream = 'audit_log';

        if (!in_array($eligibleStream, $eligible, true)) {
            // Endpoint's allowlist excludes the only stream we
            // currently support. Cursor stays put; future audit
            // streams will be picked up automatically once the
            // allowlist is reconfigured.
            return;
        }

        $watermark = $item->lastDeliveredRowId ?? 0;
        $rows = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>', 'id', $watermark])
            ->orderBy(['id' => SORT_ASC])
            ->limit(self::MAX_ROWS_PER_ENDPOINT)
            ->all();

        if (empty($rows)) {
            return;
        }

        foreach ($rows as $row) {
            try {
                $accepted = $service->dispatch($row, $item);
            } catch (Throwable $e) {
                // `dispatch()` returns bool by contract; an exception
                // here is a bug in the service, not a dispatch
                // failure. Log + stop the inner loop so we don't
                // hammer a misbehaving service.
                Craft::error(
                    'WebhookService::dispatch threw on endpoint ' . $item->id . ': ' . $e->getMessage(),
                    'password-policy',
                );

                return;
            }

            if (!$accepted) {
                // Per-endpoint failure isolation — leave the cursor at
                // the last successful row so the next job retries
                // this same row.
                return;
            }

            // Advance the watermark per-row so a partial-batch crash
            // doesn't lose progress on rows we already delivered.
            $this->_advanceWatermark((int)$item->id, (int)$row['id']);
            $item->lastDeliveredRowId = (int)$row['id'];
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Persists the endpoint's `lastDeliveredRowId` watermark. Issued
     * with a guard so a concurrent job (e.g. an admin-triggered
     * reprocess) that already advanced past `$rowId` doesn't
     * regress. Best-effort: a DB failure here is logged but never
     * rethrown — the row will surface in the next batch's query
     * regardless.
     *
     * @param int $endpointId
     * @param int $rowId
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _advanceWatermark(int $endpointId, int $rowId): void
    {
        try {
            Craft::$app->getDb()->createCommand(
                'UPDATE {{%passwordpolicy_webhook_endpoints}} '
                . 'SET [[lastDeliveredRowId]] = :rowId, [[dateUpdated]] = :now '
                . 'WHERE [[id]] = :endpointId '
                . 'AND ([[lastDeliveredRowId]] IS NULL OR [[lastDeliveredRowId]] < :rowId)',
                [
                    ':rowId' => $rowId,
                    ':now' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    ':endpointId' => $endpointId,
                ],
            )->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to advance webhook endpoint watermark for endpoint '
                . $endpointId . ': ' . $e->getMessage(),
                'password-policy',
            );
        }
    }
}
