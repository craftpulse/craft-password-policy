<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\utilities;

use Craft;
use craft\base\Utility;

use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class BlocklistUtility
 *
 * Provides a CP utility for managing the password blocklist. Displays
 * blocklist statistics and allows admins to trigger a common password
 * seed from the bundled data file.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BlocklistUtility extends Utility
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function displayName(): string
    {
        return Craft::t('password-policy', 'Password Blocklist');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function id(): string
    {
        return 'password-blocklist';
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function icon(): ?string
    {
        return Craft::getAlias('@craftpulse/passwordpolicy/icon-mask.svg');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function contentHtml(): string
    {
        $blocklistService = PasswordPolicy::$plugin->getBlocklist();

        return Craft::$app->getView()->renderTemplate('password-policy/_utilities/blocklist', [
            'commonCount' => $blocklistService->getCommonCount(),
            'customCount' => $blocklistService->getCustomWords()['total'],
            'lastUpdated' => $blocklistService->getLastUpdated(),
        ]);
    }
}
