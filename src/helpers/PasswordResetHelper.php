<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\helpers;

use Carbon\Carbon;
use craft\elements\User;
use craft\helpers\Db;

use craftpulse\passwordpolicy\PasswordPolicy;
use DateInterval;

/**
 * Class PasswordResetHelper
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordResetHelper
{
    // Public Methods
    // =========================================================================

    /**
     * Returns all active users whose password has expired according to the retention settings.
     *
     * @return User[]
     *
     * @author CraftPulse
     */
    public static function getAllUsersToExpire(): array
    {
        $interval = self::_createInterval();

        if ($interval === null) {
            return [];
        }

        $expiryDate = Carbon::now()->sub(new DateInterval($interval));

        return User::find()
            ->status('active')
            ->andWhere(['<', 'users.lastPasswordChangeDate', Db::prepareDateForDb($expiryDate)])
            ->all();
    }

    // Private Methods
    // =========================================================================

    /**
     * Creates an ISO 8601 duration string from the plugin's expiry settings.
     *
     * @return string|null
     *
     * @author CraftPulse
     */
    private static function _createInterval(): ?string
    {
        $settings = PasswordPolicy::$plugin->settings;

        return match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };
    }
}
