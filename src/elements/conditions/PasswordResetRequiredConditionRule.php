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
use craft\base\conditions\BaseLightswitchConditionRule;
use craft\base\ElementInterface;
use craft\db\Query;
use craft\db\Table;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;

/**
 * Class PasswordResetRequiredConditionRule
 *
 * Condition rule that filters users based on whether they have been
 * flagged as requiring a password reset (`passwordResetRequired = true`).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordResetRequiredConditionRule extends BaseLightswitchConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Password Reset Required');
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
        return ['passwordResetRequired'];
    }

    /**
     * Modifies the element query to filter by password reset requirement.
     *
     * @param ElementQueryInterface $query
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function modifyQuery(ElementQueryInterface $query): void
    {
        $query->andWhere(['users.passwordResetRequired' => $this->value]);
    }

    /**
     * Returns whether the given element matches this condition rule.
     *
     * `craft\elements\db\UserQuery::beforePrepare()` does NOT addSelect
     * `passwordResetRequired`, so reading it off a freshly-loaded User
     * returns its typed default (`false`) regardless of the underlying
     * column value — the ON branch would never match. Hydrate directly
     * from the users table, the same direct-scalar pattern
     * {@see PasswordExpiredConditionRule} uses for `lastPasswordChangeDate`.
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
        return $this->matchValue($this->_hydrateResetRequired($element));
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether the user is flagged as requiring a password reset,
     * read directly from the users table.
     *
     * `UserQuery::beforePrepare()` does not select `passwordResetRequired`,
     * so the in-memory `$user->passwordResetRequired` is the typed default
     * (`false`) on a freshly-loaded User regardless of DB state.
     *
     * @param User $user
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hydrateResetRequired(User $user): bool
    {
        return (bool)(new Query())
            ->select(['passwordResetRequired'])
            ->from(Table::USERS)
            ->where(['id' => $user->id])
            ->scalar();
    }
}
