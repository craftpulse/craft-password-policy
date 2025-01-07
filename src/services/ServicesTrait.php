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
 * @property PasswordsService $passwords
 * @property RetentionService $retention
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
     * @return PasswordsService The passwords service
     * @throws InvalidConfigException
     */
    public function getPasswords(): PasswordsService
    {
        return $this->get('passwords');
    }

    /**
     * Returns the retention service
     *
     * @return RetentionService The retention service
     * @throws InvalidConfigException
     */
    public function getRetention(): RetentionService
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
