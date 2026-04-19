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
use craft\base\conditions\BaseLightswitchConditionRule;
use craft\base\ElementInterface;
use craft\elements\conditions\ElementConditionRuleInterface;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craft\helpers\Db;

use craftpulse\passwordpolicy\PasswordPolicy;

use DateInterval;

/**
 * Class PasswordExpiredConditionRule
 *
 * Condition rule that filters users whose password has expired according
 * to the plugin's retention settings (expiryAmount + expiryPeriod).
 *
 * When the lightswitch is ON, the rule matches users with an expired password.
 * When OFF, it matches users whose password is still within the valid period.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordExpiredConditionRule extends BaseLightswitchConditionRule implements ElementConditionRuleInterface
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
        return Craft::t('password-policy', 'Password Expired');
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
     * Modifies the element query to filter by password expiration.
     *
     * @param ElementQueryInterface $query
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function modifyQuery(ElementQueryInterface $query): void
    {
        $expiryDate = $this->_getExpiryThreshold();

        if ($expiryDate === null) {
            return;
        }

        $operator = $this->value ? '<' : '>=';
        $query->andWhere([$operator, 'users.lastPasswordChangeDate', Db::prepareDateForDb($expiryDate)]);
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
        $expiryDate = $this->_getExpiryThreshold();

        if ($expiryDate === null) {
            return !$this->value;
        }

        if ($element->lastPasswordChangeDate === null) {
            // Users who have never changed their password are always considered expired
            return $this->value;
        }

        $isExpired = $element->lastPasswordChangeDate->getTimestamp() < $expiryDate->getTimestamp();

        return $this->matchValue($isExpired);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the expiry threshold date based on plugin settings.
     *
     * @return Carbon|null Null when retention is not configured.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getExpiryThreshold(): ?Carbon
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $interval = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };

        if ($interval === null) {
            return null;
        }

        return Carbon::now()->sub(new DateInterval($interval));
    }
}
