<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\conditions;

use Craft;
use craft\base\conditions\BaseLightswitchConditionRule;
use craft\base\ElementInterface;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;

/**
 * Class PolicyDriftConditionRule
 *
 * Pro + Craft Team-or-better filter for users whose most-recent
 * password history row's `policySnapshot` differs from the policy
 * the resolver currently picks for them. "Drift" — a user changed
 * their password under one policy, but the policy assignments
 * shifted afterwards (admin reassigned groups, edited a named
 * policy, etc.).
 *
 * Lightswitch ON ⇒ users WITH drift; OFF ⇒ users without.
 *
 * Implementation: post-resolution filter via the same
 * `UserIndexService::getStatusForUser()` resolver the table-attribute
 * column uses. Pre-load all candidate users, compute their drift,
 * narrow the query. Justification matches `PasswordStatusConditionRule`
 * — the User table is small relative to elements, and operators
 * reaching for this filter accept the slower index load.
 *
 * Registration is gated on Pro plugin AND Craft Team-or-better in
 * `PasswordPolicy::_registerUserIndexIntegration()`. Solo installs
 * have no user groups; Lite installs have no per-group resolution;
 * either way, drift can't be computed.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyDriftConditionRule extends BaseLightswitchConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Policy Drift');
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
     * Modifies the element query to filter by drift state.
     *
     * @param ElementQueryInterface $query
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function modifyQuery(ElementQueryInterface $query): void
    {
        // Pre-resolve the candidate set, then narrow. The clone
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

        $matchingIds = $this->_resolveDriftedUserIds(array_map('intval', $candidateIds));

        // Lightswitch on (value=true) → keep matching IDs.
        // Lightswitch off (value=false) → exclude matching IDs.
        if ($this->value) {
            if (empty($matchingIds)) {
                $query->andWhere(['users.id' => 0]);

                return;
            }

            $query->andWhere(['users.id' => $matchingIds]);

            return;
        }

        if (empty($matchingIds)) {
            return;
        }

        $query->andWhere(['not', ['users.id' => $matchingIds]]);
    }

    /**
     * Returns whether the given element matches the rule.
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
        if ($element->id === null) {
            return !$this->value;
        }

        $service = PasswordPolicy::$plugin->getUserIndex();
        $service->preloadForUsers([$element->id]);

        $hasDrift = $service->getStatusForUser($element) === UserIndexService::STATUS_POLICY_DRIFT;

        return $this->matchValue($hasDrift);
    }

    // Private Methods
    // =========================================================================

    /**
     * Walks each candidate user, primes the index service cache, and
     * returns the IDs whose computed status is `STATUS_POLICY_DRIFT`.
     *
     * @param int[] $candidateIds
     * @return int[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveDriftedUserIds(array $candidateIds): array
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

            if ($service->getStatusForUser($user) === UserIndexService::STATUS_POLICY_DRIFT) {
                $matching[] = (int)$user->id;
            }
        }

        return $matching;
    }
}
