<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\conditions;

use Craft;
use craft\base\conditions\BaseMultiSelectConditionRule;
use craft\base\ElementInterface;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;

/**
 * Class PasswordStatusConditionRule
 *
 * Filters users by the composite password-status badge value
 * (breached, expired, reset_required, policy_drift, expiring,
 * never_changed, ok). Multi-select so admins can combine states —
 * "show me everyone who's breached OR expired" — in a single rule.
 *
 * Query implementation: post-resolution filter via the in-memory
 * status resolver in `UserIndexService::getStatusForUser()`. The
 * computed status combines columns across three tables plus the
 * resolver's per-user policy lookup, which doesn't decompose into
 * a clean SQL filter without re-implementing the priority logic in
 * SQL. We pre-load all candidate users, compute their status, and
 * narrow the query via `andWhere(['users.id' => $matchingIds])`.
 *
 * Acceptable on the User index because (a) the User table is small
 * relative to elements, and (b) operators reaching for this filter
 * already accept slower index loads in exchange for the audit signal.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordStatusConditionRule extends BaseMultiSelectConditionRule implements ElementConditionRuleInterface
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the label for this condition rule.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getLabel(): string
    {
        return Craft::t('password-policy', 'Password Status');
    }

    /**
     * Returns the query param names this rule controls exclusively.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getExclusiveQueryParams(): array
    {
        return [];
    }

    /**
     * Modifies the element query to filter by computed password status.
     *
     * @param ElementQueryInterface $query
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function modifyQuery(ElementQueryInterface $query): void
    {
        $values = $this->getValues();

        if (empty($values)) {
            return;
        }

        // Pre-resolve the candidate user set, then narrow. The clone
        // strips status/limit/offset so the candidate population is
        // the full filtered set, not just the page being rendered.
        $candidateQuery = clone $query;
        $candidateQuery->status(null);
        $candidateQuery->limit(null);
        $candidateQuery->offset(null);
        $candidateIds = $candidateQuery->ids();

        if (empty($candidateIds)) {
            return;
        }

        $matchingIds = $this->_resolveMatchingUserIds(array_map('intval', $candidateIds), $values);

        if (empty($matchingIds)) {
            // Force the query to return no rows.
            $query->andWhere(['users.id' => 0]);

            return;
        }

        $query->andWhere(['users.id' => $matchingIds]);
    }

    /**
     * Returns whether the given element matches this condition rule.
     *
     * @param ElementInterface $element
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function matchElement(ElementInterface $element): bool
    {
        /** @var User $element */
        $values = $this->getValues();

        if (empty($values)) {
            return true;
        }

        if ($element->id === null) {
            return false;
        }

        $service = PasswordPolicy::$plugin->getUserIndex();
        $service->preloadForUsers([$element->id]);

        return in_array($service->getStatusForUser($element), $values, true);
    }

    // Protected Methods
    // =========================================================================

    /**
     * Returns the selectable status states with their labels. The
     * `policy_drift` option is hidden on installs that can't possibly
     * resolve drift (Lite plugin or Solo Craft) so admins don't pick
     * a state that always returns zero.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function options(): array
    {
        $plugin = PasswordPolicy::$plugin;
        $isPolicyDriftEligible = $plugin->getIsPro() && $plugin->isCraftTeamOrBetter();

        $labels = [
            UserIndexService::STATUS_BREACHED => Craft::t('password-policy', 'Breached'),
            UserIndexService::STATUS_EXPIRED => Craft::t('password-policy', 'Expired'),
            UserIndexService::STATUS_RESET_REQUIRED => Craft::t('password-policy', 'Reset required'),
            UserIndexService::STATUS_POLICY_DRIFT => Craft::t('password-policy', 'Policy drift'),
            UserIndexService::STATUS_EXPIRING => Craft::t('password-policy', 'Expiring soon'),
            UserIndexService::STATUS_NEVER_CHANGED => Craft::t('password-policy', 'Never changed'),
            UserIndexService::STATUS_OK => Craft::t('password-policy', 'OK'),
        ];

        if (!$isPolicyDriftEligible) {
            unset($labels[UserIndexService::STATUS_POLICY_DRIFT]);
        }

        return $labels;
    }

    // Private Methods
    // =========================================================================

    /**
     * Walks each candidate user, computes their status via the index
     * service, and returns the IDs whose status is in the selected
     * set. The preload runs once for the whole candidate batch so
     * the resolver query count stays bounded.
     *
     * @param int[] $candidateIds
     * @param string[] $statuses
     * @return int[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveMatchingUserIds(array $candidateIds, array $statuses): array
    {
        $service = PasswordPolicy::$plugin->getUserIndex();
        $service->preloadForUsers($candidateIds);

        $users = User::find()
            ->id($candidateIds)
            ->status(null)
            ->all();

        $matching = [];

        foreach ($users as $user) {
            if ($user->id === null) {
                continue;
            }

            if (in_array($service->getStatusForUser($user), $statuses, true)) {
                $matching[] = (int)$user->id;
            }
        }

        return $matching;
    }
}
