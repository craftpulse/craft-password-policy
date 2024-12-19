<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\assetbundles\passwordpolicy;

use Craft;
use craft\web\AssetBundle;
use craft\web\assets\cp\CpAsset;

use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class PasswordPolicyAsset
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordPolicyAsset extends AssetBundle
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        $this->sourcePath = '@craftpulse/passwordpolicy/web/assets/dist';
        $this->depends = [
            CpAsset::class,
        ];

        // Register Javascript variable
        Craft::$app->view->registerJsVar('passwordpolicy', [
            'showStrengthIndicator' => PasswordPolicy::$plugin->settings->showStrengthIndicator,
        ]);

        parent::init();
    }
}
