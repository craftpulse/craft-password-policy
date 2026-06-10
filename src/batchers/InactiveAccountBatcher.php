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
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class InactiveAccountBatcher
 *
 * Batchable over the inactive-account detection query (Feature 5, Pro).
 * Delegates to {@see \craftpulse\passwordpolicy\services\InactiveAccountService::findInactiveUsers()}
 * so the detection logic has a single source of truth shared with the CP
 * report surface — no duplicated WHERE clauses to drift apart.
 *
 * Recomputes the query each `getSlice()` call rather than caching the user
 * list at construction time. That gives natural idempotency on retry — a
 * user that was suspended in an earlier batch drops out of the next slice
 * (the query excludes `suspended` accounts), so a retried job never
 * double-actions.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class InactiveAccountBatcher implements Batchable
{
    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param int $thresholdDays days of inactivity before an account counts
     *     as inactive
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(
        private readonly int $thresholdDays,
    ) {
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function count(): int
    {
        return $this->_query()->count();
    }

    /**
     * @inheritdoc
     *
     * Returns User elements rather than rows so the job can call into the
     * inactive-account service with the full user model.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        $userIds = $this->_query()
            ->offset($offset)
            ->limit($limit)
            ->orderBy(['users.id' => SORT_ASC])
            ->column();

        if (empty($userIds)) {
            return [];
        }

        return User::find()
            ->id($userIds)
            ->status(null)
            ->all();
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the shared detection query from the service.
     *
     * @return Query
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _query(): Query
    {
        return PasswordPolicy::$plugin->getInactiveAccounts()
            ->findInactiveUsers($this->thresholdDays);
    }
}
