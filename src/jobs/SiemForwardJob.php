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
use craft\queue\BaseBatchedJob;
use craftpulse\passwordpolicy\batchers\UnforwardedAuditRowBatcher;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\queue\RetryableJobInterface;

/**
 * Class SiemForwardJob
 *
 * Enterprise-only batched job that forwards audit-log rows to every
 * active SIEM endpoint. Mirrors the P1.4
 * `SendPasswordExpiryRemindersJob` template (batchSize / TTR / retry
 * shape) and inherits its per-row soft-fail discipline — one bad
 * forwarder doesn't poison the batch.
 *
 * Multi-forwarder semantics: a row is "forwarded" the moment ONE
 * forwarder accepts it. Rationale: operators with multiple endpoints
 * are intentionally getting at-least-once delivery to one of them;
 * downstream SIEMs dedup on the audit row's `uid`. Different intent
 * (all-forwarders-must-succeed) is a single-condition flip in
 * `processItem` — kept explicit rather than configurable to avoid
 * over-engineering 5.2.0.
 *
 * Edition gate: the job exits early when the plugin is not running
 * Enterprise. Mirror of P1.4's pattern, with the exception that this
 * job's `execute()` does NOT throw on a sub-edition — it logs and
 * returns. Reason: the queue job can outlive an edition downgrade
 * (someone removes the Enterprise license, the plugin drops to Pro,
 * but a previously-enqueued forward job sits in the queue), and
 * crashing every retry compounds noise. Silent exit + log line is
 * the right cost there.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 *
 * @property \yii\queue\Queue $queue
 */
class SiemForwardJob extends BaseBatchedJob implements RetryableJobInterface
{
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
     * Edition gate at the very top. A queue picker that finds this job
     * on a Lite or Pro install (post-downgrade scenario) exits silently
     * after logging a warning — the row's `forwardedAt` stays NULL, no
     * forwarders run. Crashing the job on every retry would compound
     * noise without recovering anything; the right move is to leave
     * the rows for whoever re-licenses Enterprise.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            Craft::warning(
                'SiemForwardJob skipped: SIEM forwarding requires the Enterprise edition.',
                'password-policy',
            );

            return;
        }

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
        return Craft::t('password-policy', 'Forwarding audit events to SIEM endpoints');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function loadData(): UnforwardedAuditRowBatcher
    {
        return new UnforwardedAuditRowBatcher();
    }

    /**
     * @inheritdoc
     *
     * For each active forwarder eligible for the row's stream
     * (per-forwarder allowlist override or global setting), call
     * `SiemService::forward()`. On any forwarder success, mark the row
     * forwarded. On all-forwarders-fail, increment `forwardAttempts`
     * and leave `forwardedAt` NULL — the next batch retries the row.
     *
     * Per-row soft-fail in try/catch around the inner forward calls:
     * an exception thrown by the service surface (which shouldn't
     * happen — `forward()` returns bool, never throws) wouldn't
     * unwind the batch. One unreachable forwarder doesn't poison the
     * other forwarders' chances on the same row.
     *
     * @param array<string, mixed> $item the audit-log row
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function processItem(mixed $item): void
    {
        if (!is_array($item) || !isset($item['id'])) {
            return;
        }

        $rowId = (int)$item['id'];
        $service = PasswordPolicy::$plugin->getSiem();
        $forwarders = $service->getActiveForwarders();

        if (empty($forwarders)) {
            return;
        }

        $eligibleStream = 'audit_log';
        $anySucceeded = false;
        $anyAttempted = false;

        foreach ($forwarders as $forwarder) {
            if (!$this->_forwarderHandlesStream($forwarder, $eligibleStream)) {
                continue;
            }

            $anyAttempted = true;

            try {
                if ($service->forward($item, $forwarder)) {
                    $anySucceeded = true;
                }
            } catch (Throwable $e) {
                // `forward()` returns bool by contract; an exception
                // here is a bug in the service, not a forward failure.
                // Log + continue to give the row's other forwarders
                // their chance.
                Craft::error(
                    'SiemService::forward threw on forwarder ' . $forwarder->id . ': ' . $e->getMessage(),
                    'password-policy',
                );
            }
        }

        // No eligible forwarder attempted the row (e.g. allowlist
        // mismatch). Don't increment `forwardAttempts` — the row
        // wasn't actually offered to anyone, so failure semantics
        // don't apply. The row stays unforwarded; if a future
        // forwarder is registered with the matching allowlist, the
        // next batch picks it up.
        if (!$anyAttempted) {
            return;
        }

        $this->_recordRowOutcome($rowId, $anySucceeded);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether the forwarder is configured to handle the given
     * stream (e.g. `audit_log`). Per-forwarder override wins; otherwise
     * the global setting via the service.
     *
     * @param SiemForwarderModel $forwarder
     * @param string $stream
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _forwarderHandlesStream(SiemForwarderModel $forwarder, string $stream): bool
    {
        $eligible = PasswordPolicy::$plugin->getSiem()
            ->getEligibleEventClasses($forwarder);

        return in_array($stream, $eligible, true);
    }

    /**
     * Writes the outcome of a row's forward attempts back to
     * `passwordpolicy_audit_log`. On success: `forwardedAt = NOW()`.
     * On failure (no forwarder accepted): `forwardAttempts++` and
     * `forwardedAt` stays NULL so the next batch retries.
     *
     * Best-effort: a DB failure here is logged but not rethrown. The
     * row will surface in the next batch's query regardless.
     *
     * @param int $rowId
     * @param bool $succeeded
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordRowOutcome(int $rowId, bool $succeeded): void
    {
        try {
            if ($succeeded) {
                Craft::$app->getDb()->createCommand()
                    ->update(
                        '{{%passwordpolicy_audit_log}}',
                        ['forwardedAt' => Carbon::now('UTC')->format('Y-m-d H:i:s')],
                        ['id' => $rowId],
                    )
                    ->execute();

                return;
            }

            // All forwarders failed — bump the attempts counter. Use a
            // raw SQL increment so concurrent batches can't race on a
            // read-modify-write.
            Craft::$app->getDb()->createCommand(
                'UPDATE {{%passwordpolicy_audit_log}} SET [[forwardAttempts]] = [[forwardAttempts]] + 1 WHERE [[id]] = :id',
                [':id' => $rowId],
            )->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to record audit-log forward outcome for row ' . $rowId . ': ' . $e->getMessage(),
                'password-policy',
            );
        }
    }
}
