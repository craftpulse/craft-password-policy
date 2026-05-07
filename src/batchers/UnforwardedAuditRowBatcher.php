<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
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
 * Re-queries each `getSlice()` call rather than caching the row list
 * at construction time. Same campaign-style idempotency as
 * {@see ExpiringPasswordUserBatcher}: a job that partially completes
 * (some rows forwarded, `forwardedAt` set) and is retried picks up
 * exactly where it left off — already-forwarded rows drop out of the
 * query naturally on the next slice.
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
     * Returns raw row arrays. The job uses each row both to build the
     * syslog frame and to look up `id` for the `forwardedAt` write
     * back, so the full row shape is wanted.
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
        return (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['forwardedAt' => null])
            ->orderBy(['id' => SORT_ASC]);
    }
}
