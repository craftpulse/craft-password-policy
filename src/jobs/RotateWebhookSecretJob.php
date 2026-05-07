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
use craft\queue\BaseJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;
use Throwable;

/**
 * Class RotateWebhookSecretJob
 *
 * One-shot job that nulls `secretPrevious` on a webhook endpoint after
 * the configured rotation grace window has elapsed (G9). Pushed onto
 * the queue at rotation time by `WebhookEndpointController::actionRotateSecret`
 * with `delay = webhookSecretGracePeriodHours * 3600`.
 *
 * Idempotent: if `secretPrevious` is already null OR the grace window
 * hasn't elapsed (e.g. `secretRotatedAt` was reset by a subsequent
 * rotation), the job no-ops. Two consecutive rotations within the
 * grace window enqueue two reaper jobs; the first is a no-op against
 * the new (more recent) rotation timestamp, the second runs as
 * expected.
 *
 * Edition gate: deferred to Enterprise. Same rationale as
 * `WebhookForwardJob` — the queue can outlive an edition downgrade.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 *
 * @property \yii\queue\Queue $queue
 */
class RotateWebhookSecretJob extends BaseJob
{
    // Public Properties
    // =========================================================================

    /**
     * @var int the webhook endpoint id whose `secretPrevious` should
     *     be reaped after the grace window. Required.
     */
    public int $endpointId;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            Craft::warning(
                'RotateWebhookSecretJob skipped — webhook secret rotation requires the Enterprise edition.',
                'password-policy',
            );

            return;
        }

        /** @var WebhookEndpointRecord|null $record */
        $record = WebhookEndpointRecord::findOne(['id' => $this->endpointId]);

        if ($record === null) {
            // Endpoint was deleted between rotation and grace expiry.
            // Nothing to reap.
            return;
        }

        if ($record->secretPrevious === null || $record->secretPrevious === '') {
            // Already reaped — concurrent run, or the operator
            // manually nulled the previous secret.
            return;
        }

        if (!$this->_gracePeriodElapsed($record)) {
            // The endpoint was re-rotated after this job was enqueued;
            // a fresh reaper is in flight against the new timestamp.
            // No-op.
            return;
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    WebhookEndpointRecord::tableName(),
                    [
                        'secretPrevious' => null,
                        'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    ],
                    ['id' => $this->endpointId],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to reap webhook endpoint secret '
                . $this->endpointId . ': ' . $e->getMessage(),
                'password-policy',
            );
        }
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
        return Craft::t(
            'password-policy',
            'Reaping previous webhook secret for endpoint {id}',
            ['id' => $this->endpointId],
        );
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether the configured grace window has elapsed since
     * `secretRotatedAt`. Defensive default: when the column is null
     * (rotation didn't pin it for some reason — shouldn't happen in
     * normal flow), treat the grace window as elapsed so the reaper
     * still runs and clears stale state.
     *
     * @param WebhookEndpointRecord $record
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _gracePeriodElapsed(WebhookEndpointRecord $record): bool
    {
        $rotatedAt = $record->secretRotatedAt;

        if ($rotatedAt === null) {
            return true;
        }

        $graceHours = PasswordPolicy::$plugin->getSettings()->webhookSecretGracePeriodHours;
        $graceSeconds = max(1, $graceHours) * 3600;

        $elapsed = Carbon::now('UTC')->getTimestamp()
            - Carbon::parse($rotatedAt)->getTimestamp();

        return $elapsed >= $graceSeconds;
    }
}
