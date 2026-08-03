<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\batchers;

use Carbon\Carbon;
use craft\base\Batchable;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;

/**
 * Class WebhookEndpointBatcher
 *
 * Batchable for active webhook endpoints (G9). Drives the outer loop
 * of `WebhookForwardJob` — the job processes one endpoint per
 * `processItem` call, each time consuming up to N audit rows past the
 * endpoint's `lastDeliveredRowId` watermark. Differs from the SIEM
 * forwarder shape (rows in the outer loop) because webhooks track per-
 * endpoint dispatch state independently.
 *
 * Re-queries each `getSlice()` call rather than caching the endpoint
 * list at construction time. Same campaign-style idempotency as the
 * SIEM batcher: a job that partially completes and is retried picks
 * up exactly where it left off — endpoints with newly-tripped
 * circuits drop out of the next slice naturally via
 * `getActiveEndpoints()`'s where-clause.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookEndpointBatcher implements Batchable
{
    // Public Methods
    // =========================================================================

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
     * Returns hydrated `WebhookEndpointModel` instances. The job's
     * `processItem` consumes the model directly so the secret is
     * already decrypted by the time dispatch needs it.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        $rows = $this->_buildQuery()
            ->offset($offset)
            ->limit($limit)
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var WebhookEndpointRecord $row */
            $models[] = WebhookEndpointModel::fromRecord($row);
        }

        return $models;
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds the active-endpoints query used by both `count()` and
     * `getSlice()`. Mirrors `WebhookService::getActiveEndpoints()` but
     * returns records (not models) so the slice hydration stays in
     * one place.
     *
     * @return \yii\db\ActiveQuery
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildQuery(): \yii\db\ActiveQuery
    {
        $cooldownSeconds = PasswordPolicy::$plugin->getSettings()->webhookCircuitCooldownSeconds;
        $cooldownThreshold = Carbon::now('UTC')
            ->subSeconds($cooldownSeconds > 0 ? $cooldownSeconds : 300)
            ->format('Y-m-d H:i:s');

        return WebhookEndpointRecord::find()
            ->where(['enabled' => true])
            ->andWhere([
                'or',
                ['circuitOpenAt' => null],
                ['<=', 'circuitOpenAt', $cooldownThreshold],
            ])
            ->orderBy(['id' => SORT_ASC]);
    }
}
