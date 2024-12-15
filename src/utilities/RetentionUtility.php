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
 * Class RetentionUtility
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class RetentionUtility extends Utility
{
    /**
     * @inheritdoc
     */
    public static function displayName(): string
    {
        return Craft::t('password-policy', 'Password Retention');
    }

    /**
     * @inheritdoc
     */
    public static function id(): string
    {
        return 'password-retention';
    }

    /**
     * @inheritdoc
     */
    public static function icon(): ?string
    {
        return Craft::getAlias('@craftpulse/passwordpolicy/icon-mask.svg');
    }

    /**
     * @inheritdoc
     */
    public static function contentHtml(): string
    {
        return Craft::$app->getView()->renderTemplate('password-policy/_utilities/retention', [
            'actions' => self::getActions(),
        ]);
    }

    /**
     * @return array
     */
    public static function getActions(): array
    {
        $actions = [];

        $actions[] = [
            'id' => 'force-reset-passwords',
            'label' => Craft::t('password-policy', 'Force Reset Passwords'),
            'instructions' => Craft::t('password-policy', "Force reset passwords that don't comply with your expiration settings.")
        ];

        return $actions;
    }
}
