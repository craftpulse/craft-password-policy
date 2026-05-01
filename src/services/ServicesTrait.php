<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use craftpulse\passwordpolicy\assetbundles\passwordpolicy\PasswordPolicyAsset;
use nystudio107\pluginvite\services\VitePluginService;
use yii\base\InvalidConfigException;

/**
 * @author    CraftPulse
 * @package   Password Policy
 * @since     5.0.3
 *
 * @property PasswordService $passwords
 * @property RetentionService $retention
 * @property SecurityService $security
 * @property VitePluginService $vite
 */
trait ServicesTrait
{
    // Static Methods
    // =========================================================================

    /**
     * Returns the component configuration for this plugin.
     *
     * @return array
     *
     * @author CraftPulse
     */
    public static function config(): array
    {
        return [
            'components' => [
                'passwords' => PasswordService::class,
                'retention' => RetentionService::class,
                'security' => SecurityService::class,
                // Register the vite service
                // @TODO devServerPublic / devServerInternal / serverPublic would benefit of `.env` vars for local dev
                'vite' => [
                    'assetClass' => PasswordPolicyAsset::class,
                    'checkDevServer' => true,
                    'useForAllRequests' => true,
                    'class' => VitePluginService::class,
                    'devServerInternal' => 'http://craft-password-policy-v5-buildchain-dev:3005',
                    'devServerPublic' => 'http://localhost:3005',
                    'errorEntry' => 'src/js/indicator.ts',
                    'useDevServer' => true,
                ],
            ],
        ];
    }

    // Public Methods
    // =========================================================================

    /**
     * Returns the passwords service.
     *
     * @return PasswordService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     */
    public function getPasswords(): PasswordService
    {
        return $this->get('passwords');
    }

    /**
     * Returns the retention service.
     *
     * @return RetentionService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     */
    public function getRetention(): RetentionService
    {
        return $this->get('retention');
    }

    /**
     * Returns the security service.
     *
     * @return SecurityService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     */
    public function getSecurity(): SecurityService
    {
        return $this->get('security');
    }

    /**
     * Returns the vite service.
     *
     * @return VitePluginService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     */
    public function getVite(): VitePluginService
    {
        return $this->get('vite');
    }
}
