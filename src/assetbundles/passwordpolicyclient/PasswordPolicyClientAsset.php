<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\assetbundles\passwordpolicyclient;

use craft\web\AssetBundle;
use craft\web\View;

/**
 * Class PasswordPolicyClientAsset
 *
 * Front-end client asset bundle for the consumer-facing render builders
 * (PasswordFieldTag with `liveValidation: true`, PasswordChangeFormTag,
 * PasswordResetFormTag, PasswordWidgetTag).
 *
 * Vanilla JavaScript, no framework dependency, no Vite assumption on the
 * consumer side. Auto-registered by the relevant tag classes when their
 * `liveValidation` flag is on.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordPolicyClientAsset extends AssetBundle
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function init(): void
    {
        $this->sourcePath = '@craftpulse/passwordpolicy/web/assets/passwordpolicyclient/';

        $this->js = [
            ['password-policy.js', 'position' => View::POS_END],
        ];

        $this->css = [
            'password-policy.css',
        ];

        parent::init();
    }
}
