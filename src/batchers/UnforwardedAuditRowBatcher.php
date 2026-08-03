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

use craft\base\Batchable;
use craft\db\Query;

/**
 * Class UnforwardedAuditRowBatcher
 *
 * Batchable for audit-log rows awaiting SIEM forwarding (G8). Selects
 * rows where `forwardedAt IS NULL` ordered by `id ASC` — natural
 * insertion order means downstream SIEMs receive events in the order
 * they happened on the originating site.
 *
 * ## Why this paginates by watermark and not by offset
 *
 * The forwardable predicate is SELF-CONSUMING: `SiemForwardJob` sets
 * `forwardedAt` on every row it delivers, so each processed row leaves the
 * result set. `craft\queue\BaseBatchedJob` meanwhile advances `itemOffset`
 * monotonically across the batches it spawns. An offset-paginated
 * `getSlice()` therefore skips exactly as many rows as it processed: with
 * a batch size of 100 and 250 pending rows, the second batch asks for rows
 * 101-200 of a result set that now holds 150, and the job reports clean
 * completion having forwarded roughly half the trail. Audit rows never
 * reaching the SIEM is the precise failure a compliance trail exists to
 * prevent, so this is not a tolerable rounding error.
 *
 * The fix is the watermark pattern already used by
 * {@see \craftpulse\passwordpolicy\jobs\WebhookForwardJob::processItem()}:
 * pagination is keyed on the last id the campaign consumed rather than on
 * a row count. Two constructor arguments carry the campaign's position,
 * both fed from public properties on the job so they survive the
 * `clone` + serialize that spawns the next batch:
 *
 *  - `$afterId` bounds the slice to `id > $afterId`, so `$offset` is
 *    ignored entirely and no row is ever handed out twice.
 *  - `$processedCount` is added back into `count()`, because
 *    `BaseBatchedJob` terminates on `itemOffset < totalItems()` and a
 *    shrinking total would strand the tail of the campaign.
 *
 * A row that every forwarder rejects keeps `forwardedAt = NULL` and sits
 * BELOW the watermark, so it is skipped for the rest of the campaign and
 * retried by the next scheduled run (which starts from a null watermark).
 * That is deliberate: re-offering a permanently failing row inside the
 * same campaign would grow `count()` on every batch and the job would
 * never terminate.
 *
 * The batcher does NOT filter by event class; the queue job's
 * `processItem` consults the per-forwarder + global allowlist on the
 * model side. Stream-based filtering (e.g. excluding
 * `notification_log` until 5.3 ships) lives in the service.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UnforwardedAuditRowBatcher implements Batchable
{
    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param int|null $afterId the highest audit-row id the campaign has
     *     already consumed; null starts a fresh campaign
     * @param int $processedCount how many rows earlier batches of this
     *     campaign already consumed, added back into {@see self::count()}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        private readonly ?int $afterId = null,
        private readonly int $processedCount = 0,
    ) {
    }

    /**
     * @inheritdoc
     *
     * Rows this campaign already consumed plus the rows still pending past
     * the watermark. The offset `BaseBatchedJob` compares against is
     * cumulative across batches, so a bare remaining-rows count would fall
     * below it and end the campaign early.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function count(): int
    {
        return $this->processedCount + $this->_buildQuery()->count();
    }

    /**
     * @inheritdoc
     *
     * Returns raw row arrays. The job uses each row both to build the
     * syslog frame and to look up `id` for the `forwardedAt` write
     * back, so the full row shape is wanted.
     *
     * `$offset` is deliberately unused: the slice is bounded by the
     * campaign's watermark instead. See the class docblock.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        return $this->_buildQuery()
            ->limit($limit)
            ->all();
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds the unforwarded-rows query. `forwardedAt IS NULL` is the
     * forwardable predicate; `id ASC` preserves originating order so
     * SIEM consumers see events in the order they happened.
     *
     * @return Query
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildQuery(): Query
    {
        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['forwardedAt' => null])
            ->orderBy(['id' => SORT_ASC]);

        if ($this->afterId !== null) {
            $query->andWhere(['>', 'id', $this->afterId]);
        }

        return $query;
    }
}
