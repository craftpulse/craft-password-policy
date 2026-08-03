<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\utilities;

use Craft;
use craft\base\Utility;

/**
 * Class RetentionUtility
 *
 * The Password Retention utility. Hosts the mass force-reset action, which
 * flags every account already past the configured expiry window.
 *
 * Registered on every edition, deliberately. The mass path shipped in 5.1.2,
 * before the plugin had editions, so gating it would withdraw a capability
 * existing installs already have. Per-user force reset is the additive Pro
 * capability and lives on the user-edit surfaces instead.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class RetentionUtility extends Utility
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public static function displayName(): string
    {
        return Craft::t('password-policy', 'Password Retention');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public static function id(): string
    {
        return 'password-retention';
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public static function icon(): ?string
    {
        return Craft::getAlias('@craftpulse/passwordpolicy/icon-mask.svg');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public static function contentHtml(): string
    {
        return Craft::$app->getView()->renderTemplate('password-policy/_utilities/retention', [
            'actions' => self::_getActions(),
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the available retention actions.
     *
     * @return array
     *
     * @author CraftPulse
     */
    private static function _getActions(): array
    {
        $actions = [];

        $actions[] = [
            'id' => 'force-reset-passwords',
            'label' => Craft::t('password-policy', 'Force Reset Passwords'),
            'instructions' => Craft::t('password-policy', "Force reset passwords that don't comply with your expiration settings."),
        ];

        return $actions;
    }
}
