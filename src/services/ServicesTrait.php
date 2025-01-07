<?php

namespace craftpulse\passwordpolicy\services;

use craftpulse\passwordpolicy\assetbundles\passwordpolicy\PasswordPolicyAsset;
use nystudio107\pluginvite\services\VitePluginService;
use yii\base\InvalidConfigException;

/**
 * @author    craftpulse
 * @package   Password Policy
 * @since     5.0.3
 *
 * @property Passwords $passwords
 * @property Retention $retention
 * @property VitePluginService $vite
 */
trait ServicesTrait
{
    public static function config(): array
    {
        return [
            'components' => [
                'passwords' => PasswordService::class,
                'retention' => RetentionService::class,
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
     * Returns the passwords service
     *
     * @return Events The events service
     * @throws InvalidConfigException
     */
    public function getPasswords(): Events
    {
        return $this->get('passwords');
    }

    /**
     * Returns the retention service
     *
     * @return Redirects The redirects service
     * @throws InvalidConfigException
     */
    public function getRetention(): Redirects
    {
        return $this->get('retention');
    }

    /**
     * Returns the vite service
     *
     * @return VitePluginService The vite service
     * @throws InvalidConfigException
     */
    public function getVite(): VitePluginService
    {
        return $this->get('vite');
    }
}
