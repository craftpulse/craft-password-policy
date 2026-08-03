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
use craft\db\Query;

/**
 * Class AuditExportBatcher
 *
 * Batchable for audit-log rows inside a date range — drives the G10
 * `AuditExportJob`. Selects rows where `dateCreated >= NOW() - daysFilter`
 * ordered by `id ASC` so the export file's row order matches the
 * canonical insertion order (the same order the chain verifier walks).
 *
 * Mirrors the campaign-style re-query idiom from
 * {@see UnforwardedAuditRowBatcher} (G8) and
 * {@see ExpiringPasswordUserBatcher} (P1.4): each `getSlice()` call
 * re-runs the query rather than caching the row list at construction
 * time. A job that partially completes and is retried picks up cleanly
 * — the date-bounded query produces a stable result set as long as no
 * audit-log purge runs mid-export, and the row order is stable on `id
 * ASC`. (Concurrent inserts during export append to the tail and are
 * naturally excluded by the original threshold's NOW value, captured
 * once on job enqueue and passed through as `$daysFilter`.)
 *
 * The batcher does NOT filter by event class — exports include every
 * row in the date range. If a future operator wants per-event-class
 * exports, that's a builder argument added to the job + a `WHERE event
 * IN (...)` clause here.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditExportBatcher implements Batchable
{
    // Public Properties
    // =========================================================================

    /**
     * @var int the number of days back from NOW() to include in the
     *     export. Captured at job-enqueue time and passed through the
     *     queue payload, so the threshold is stable across retries.
     */
    public int $daysFilter;

    // Public Methods
    // =========================================================================

    /**
     * @param int $daysFilter
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(int $daysFilter)
    {
        $this->daysFilter = $daysFilter;
    }

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
     * Returns raw row arrays. The job needs every column the canonical
     * payload references plus `id` for ordering and `rowHash` /
     * `previousHash` for the JSONL output (auditors verifying the file
     * against the chain expect both columns visible).
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        return $this->_buildQuery()
            ->offset($offset)
            ->limit($limit)
            ->all();
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds the date-bounded export query. Threshold is captured as a
     * UTC datetime string; `id ASC` preserves canonical insertion order.
     *
     * @return Query
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildQuery(): Query
    {
        $threshold = Carbon::now('UTC')
            ->subDays($this->daysFilter)
            ->format('Y-m-d H:i:s');

        return (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>=', 'dateCreated', $threshold])
            ->orderBy(['id' => SORT_ASC]);
    }
}
