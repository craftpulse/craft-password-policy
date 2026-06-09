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
     *
     * @author CraftPulse
     */
    public function init(): void
    {
        $this->sourcePath = '@craftpulse/passwordpolicy/web/assets/dist/';
        $this->depends = [
            CpAsset::class,
        ];

        // Surface the `showStrengthIndicator` flag as a <meta> tag rather
        // than an inline `registerJs` bootstrap. A bare inline <script> has
        // no CSP nonce, so under a strict-nonce policy (which the indicator
        // script DOES carry, via `cspNonce`) the browser blocks the bootstrap
        // and the meter never boots. A <meta> tag is not script-src governed,
        // so it survives any CSP. The nonced indicator script reads the flag
        // from this tag (with a `window.passwordpolicy` fallback for legacy
        // consumers).
        Craft::$app->getView()->registerMetaTag([
            'name' => 'pp-show-strength-indicator',
            'content' => PasswordPolicy::$plugin->getSettings()->showStrengthIndicator ? '1' : '0',
        ], 'pp-show-strength-indicator');

        parent::init();
    }
}
