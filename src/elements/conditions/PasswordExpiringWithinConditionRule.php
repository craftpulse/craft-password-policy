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

use Carbon\Carbon;
use Craft;
use craft\base\conditions\BaseNumberConditionRule;
use craft\base\ElementInterface;
use craft\db\Query;
use craft\db\Table;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craft\helpers\DateTimeHelper;
use craft\helpers\Db;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateInterval;

/**
 * Class PasswordExpiringWithinConditionRule
 *
 * Filters users whose password is set to expire within the configured
 * lookahead window. Distinct from {@see PasswordExpiredConditionRule}
 * — that rule asks the boolean "expired yes/no" question; this rule
 * asks "expiring within N days." Operators commonly need both:
 *
 *  - "Find everyone whose password has already expired" → lightswitch.
 *  - "Find everyone whose password expires within the next 14 days
 *    so we can email a heads-up" → this rule.
 *
 * No-op when the plugin's expiry window isn't configured (`expiryAmount`
 * null or zero) — the rule's input still renders but matches nothing.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordExpiringWithinConditionRule extends BaseNumberConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Password Expiring Within (days)');
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
     * Modifies the element query to filter by password expiration
     * within a configurable lookahead window.
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
        $threshold = $this->_getExpiringCutoff($window);

        if ($threshold === null) {
            return;
        }

        // Users whose lastPasswordChangeDate is older than (now - expiry
        // + N days) are due to expire within N days. The same SQL works
        // for "expiring in 0 days" (already expired) and "expiring in
        // 14 days" (lookahead).
        $query->andWhere(['<', 'users.lastPasswordChangeDate', Db::prepareDateForDb($threshold)]);
    }

    /**
     * Returns whether the given element matches the rule.
     *
     * `craft\elements\db\UserQuery::beforePrepare()` does NOT addSelect
     * `lastPasswordChangeDate`, so reading it off a freshly-loaded User
     * returns null regardless of the underlying column value — every
     * user would look never-changed and match. Hydrate directly from the
     * users table, mirroring {@see PasswordExpiredConditionRule::matchElement()}.
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
        $threshold = $this->_getExpiringCutoff($window);

        if ($threshold === null) {
            return false;
        }

        $lastChange = $this->_hydrateLastChange($element);

        if ($lastChange === null) {
            // Never-changed users are due to expire under any window.
            return true;
        }

        return $lastChange->getTimestamp() < $threshold->getTimestamp();
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the cutoff point: passwords whose `lastPasswordChangeDate`
     * is older than this point will expire within `$window` days.
     * Returns null when no expiry policy is configured.
     *
     * @param int $window
     * @return Carbon|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getExpiringCutoff(int $window): ?Carbon
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $intervalSpec = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };

        if ($intervalSpec === null) {
            return null;
        }

        // Cutoff = now - expiry + window. Anything older than this will
        // expire within `$window` days from now.
        $cutoff = Carbon::now()->sub(new DateInterval($intervalSpec));

        if ($window > 0) {
            $cutoff = $cutoff->addDays($window);
        }

        return $cutoff;
    }

    /**
     * Returns the user's `lastPasswordChangeDate`, preferring the
     * in-memory value and falling back to a direct DB scalar query when
     * the property is null (the correct path on a freshly-loaded User —
     * `UserQuery::beforePrepare()` does not select the column).
     *
     * @param User $user
     * @return \DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hydrateLastChange(User $user): ?\DateTime
    {
        if ($user->lastPasswordChangeDate !== null) {
            return $user->lastPasswordChangeDate;
        }

        $raw = (new Query())
            ->select(['lastPasswordChangeDate'])
            ->from(Table::USERS)
            ->where(['id' => $user->id])
            ->scalar();

        if ($raw === false || $raw === null || $raw === '') {
            return null;
        }

        return DateTimeHelper::toDateTime($raw) ?: null;
    }
}
