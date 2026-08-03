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
use craft\db\Query;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craftpulse\passwordpolicy\enums\ChangeReason;

/**
 * Class LastChangeReasonConditionRule
 *
 * Filters users by the `changeReason` value on their most-recent
 * `passwordpolicy_password_history` row. Multi-select on
 * {@see ChangeReason::cases()} so admins can pick "all users whose
 * last change was a self-service flow" or "all users whose last
 * change was a breach-forced reset."
 *
 * Implementation pattern: subquery joining each user to their newest
 * history row's reason. Costlier than the lightswitch rules; accept
 * the cost on the User index because operators get real value from
 * the filter axis.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class LastChangeReasonConditionRule extends BaseMultiSelectConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Last Password Change Reason');
    }

    /**
     * Returns the query param names this rule controls exclusively.
     * The history table isn't exposed via UserQuery so we own the
     * subquery shape — this list is empty.
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
     * Modifies the element query to restrict to users whose most-recent
     * history row's `changeReason` is in the selected set.
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

        // Build a subquery returning userId for users whose latest
        // history row matches one of the selected reasons.
        $latest = (new Query())
            ->select(['userId', 'maxDate' => 'MAX([[dateCreated]])'])
            ->from('{{%passwordpolicy_password_history}}')
            ->groupBy(['userId']);

        $matchingUsers = (new Query())
            ->select(['h.userId'])
            ->from(['h' => '{{%passwordpolicy_password_history}}'])
            ->innerJoin(
                ['latest' => $latest],
                '[[h.userId]] = [[latest.userId]] AND [[h.dateCreated]] = [[latest.maxDate]]',
            )
            ->where(['h.changeReason' => $values]);

        $query->andWhere(['users.id' => $matchingUsers]);
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

        $latestReason = (new Query())
            ->select(['changeReason'])
            ->from('{{%passwordpolicy_password_history}}')
            ->where(['userId' => $element->id])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit(1)
            ->scalar();

        if ($latestReason === false) {
            return false;
        }

        return in_array($latestReason, $values, true);
    }

    // Protected Methods
    // =========================================================================

    /**
     * Returns the available `ChangeReason` cases as `value => label`
     * pairs for the multi-select input.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function options(): array
    {
        $options = [];

        foreach (ChangeReason::cases() as $case) {
            $options[$case->value] = $case->label();
        }

        return $options;
    }
}
