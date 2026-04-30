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
 * @property AuditLogService $auditLog
 * @property BlocklistService $blocklist
 * @property PasswordHistoryService $passwordHistory
 * @property NotificationService $notification
 * @property PasswordService $passwords
 * @property PolicyService $policies
 * @property PolicyResolverService $policyResolver
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
                'auditLog' => AuditLogService::class,
                'blocklist' => BlocklistService::class,
                'passwordHistory' => PasswordHistoryService::class,
                'notification' => NotificationService::class,
                'passwords' => PasswordService::class,
                'policies' => PolicyService::class,
                'policyResolver' => PolicyResolverService::class,
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
     * Returns the audit log service.
     *
     * @return AuditLogService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAuditLog(): AuditLogService
    {
        return $this->get('auditLog');
    }

    /**
     * Returns the blocklist service.
     *
     * @return BlocklistService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getBlocklist(): BlocklistService
    {
        return $this->get('blocklist');
    }

    /**
     * Returns the password history service.
     *
     * @return PasswordHistoryService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPasswordHistory(): PasswordHistoryService
    {
        return $this->get('passwordHistory');
    }

    /**
     * Returns the notification service.
     *
     * @return NotificationService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getNotification(): NotificationService
    {
        return $this->get('notification');
    }

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
     * Returns the policies service.
     *
     * @return PolicyService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPolicies(): PolicyService
    {
        return $this->get('policies');
    }

    /**
     * Returns the policy resolver service.
     *
     * @return PolicyResolverService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPolicyResolver(): PolicyResolverService
    {
        return $this->get('policyResolver');
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
