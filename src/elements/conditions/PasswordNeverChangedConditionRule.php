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

/**
 * Class PasswordNeverChangedConditionRule
 *
 * Condition rule that filters users who have never changed their password,
 * identified by `lastPasswordChangeDate IS NULL`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordNeverChangedConditionRule extends BaseLightswitchConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Password Never Changed');
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
        return ['lastPasswordChangeDate'];
    }

    /**
     * Modifies the element query to filter by whether the password was never changed.
     *
     * @param ElementQueryInterface $query
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function modifyQuery(ElementQueryInterface $query): void
    {
        if ($this->value) {
            $query->andWhere(['users.lastPasswordChangeDate' => null]);
        } else {
            $query->andWhere(['not', ['users.lastPasswordChangeDate' => null]]);
        }
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
        $neverChanged = $element->lastPasswordChangeDate === null;

        return $this->matchValue($neverChanged);
    }
}
