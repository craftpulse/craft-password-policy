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

use Carbon\Carbon;
use Craft;
use craft\base\conditions\BaseNumberConditionRule;
use craft\base\ElementInterface;
use craft\db\Query;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craft\helpers\Db;

/**
 * Class BreachedRecentlyConditionRule
 *
 * Pro-only filter for users whose `passwordpolicy_user_state.lastBreachDetectedAt`
 * is within the configured lookback window (in days). Mirrors the
 * `passwordpolicy_breached` table-attribute column from D2.1 and
 * narrows it: instead of "ever breached," ask "breached within N
 * days." Operators triaging an incident commonly want the recent
 * subset, not the historical lifetime.
 *
 * Lite installs don't register this rule (gated at registration
 * time in `PasswordPolicy::_registerUserIndexIntegration()`).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BreachedRecentlyConditionRule extends BaseNumberConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Breached Within (days)');
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
     * Modifies the element query to restrict to users with a recent
     * breach detection.
     *
     * @param ElementQueryInterface $query
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function modifyQuery(ElementQueryInterface $query): void
    {
        $window = (int)$this->value;

        if ($window <= 0) {
            return;
        }

        $cutoff = Carbon::now('UTC')->subDays($window);

        $matchingUsers = (new Query())
            ->select(['userId'])
            ->from('{{%passwordpolicy_user_state}}')
            ->where(['>=', 'lastBreachDetectedAt', Db::prepareDateForDb($cutoff)]);

        $query->andWhere(['users.id' => $matchingUsers]);
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
        $window = (int)$this->value;

        if ($window <= 0 || $element->id === null) {
            return false;
        }

        $detectedAt = (new Query())
            ->select(['lastBreachDetectedAt'])
            ->from('{{%passwordpolicy_user_state}}')
            ->where(['userId' => $element->id])
            ->scalar();

        if ($detectedAt === false || $detectedAt === null) {
            return false;
        }

        $cutoff = Carbon::now('UTC')->subDays($window);

        // `lastBreachDetectedAt` is a naive UTC string (Craft's standard
        // datetime column convention). `Carbon::parse()` without an
        // explicit timezone interprets naive input in the AMBIENT process
        // timezone (`system.timeZone`), shifting the comparison against
        // `$cutoff` by the full UTC offset on any non-UTC install.
        return Carbon::parse((string)$detectedAt, 'UTC')->greaterThanOrEqualTo($cutoff);
    }
}
