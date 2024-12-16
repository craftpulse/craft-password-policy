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

use craftpulse\passwordpolicy\PasswordPolicy;
use DateTime;

/**
 * Class PasswordResetHelper
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordResetHelper
{
    /**
     * Returns all the users where the password should be expired.
     *
     * @return array
     */
    public static function getAllUsersToExpire(): array
    {
        // make sure we have the lastPasswordChangeDate on our users
        $users = User::find()->addSelect('lastPasswordChangeDate')->collect();

        // only get the active users
        $users = $users->filter(function($user) {
            return $user->active === true;
        });

        // now only get the ones where their password is changed at least 90 days ago (how lol?);
        $users = $users->filter(function($user) {
            return self::checkIfExpired($user->lastPasswordChangeDate);
        })->all();

        return $users;
    }

    private static function checkIfExpired(?DateTime $lastPasswordChangeDate = null): bool
    {
        if ($lastPasswordChangeDate === null) {
            return false;
        }

        $now = Carbon::now();
        $interval = self::createInterval();
        $lastPasswordChangeDate = new Carbon($lastPasswordChangeDate);
        if ($interval) {
            $requiredLastPasswordChangeDate = $now->subtract(self::createInterval());
            if ($lastPasswordChangeDate->lessThan($requiredLastPasswordChangeDate)) {
                return true;
            };
        }

        return false;
    }

    private static function createInterval(): ?string
    {
        $settings = PasswordPolicy::$plugin->settings;
        $period = null;

        switch ($settings->expiryPeriod) {
            case 'day':
                $period = "P{$settings->expiryAmount}D";
                break;
            case 'week':
                $period = "P{$settings->expiryAmount}W";
                break;
            case 'month':
                $period = "P{$settings->expiryAmount}M";
                break;
            case 'year':
                $period = "P{$settings->expiryAmount}Y";
                break;
        }

        return $period;
    }
}
