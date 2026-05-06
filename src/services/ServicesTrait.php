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
 * @property HibpClientInterface $hibpClient
 * @property PasswordHistoryService $passwordHistory
 * @property NotificationService $notification
 * @property NotificationActivityService $notificationActivity
 * @property NotificationTemplateService $notificationTemplates
 * @property PasswordService $passwords
 * @property PolicyService $policies
 * @property PolicyResolverService $policyResolver
 * @property RegistrationService $registration
 * @property RetentionService $retention
 * @property SecurityService $security
 * @property StrengthService $strength
 * @property UserIndexService $userIndex
 * @property UserStateService $userState
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
                'hibpClient' => GuzzleHibpClient::class,
                'passwordHistory' => PasswordHistoryService::class,
                'notification' => NotificationService::class,
                'notificationActivity' => NotificationActivityService::class,
                'notificationTemplates' => NotificationTemplateService::class,
                'passwords' => PasswordService::class,
                'policies' => PolicyService::class,
                'policyResolver' => PolicyResolverService::class,
                'registration' => RegistrationService::class,
                'retention' => RetentionService::class,
                'security' => SecurityService::class,
                'strength' => StrengthService::class,
                'userIndex' => UserIndexService::class,
                'userState' => UserStateService::class,
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
     * Returns the HIBP range-API client.
     *
     * Decoupled behind an interface so tests can swap in a fake without
     * hitting the live endpoint. Production binds `GuzzleHibpClient`.
     *
     * @return HibpClientInterface
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getHibpClient(): HibpClientInterface
    {
        return $this->get('hibpClient');
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
     * Returns the notification activity (read-side) service.
     *
     * @return NotificationActivityService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getNotificationActivity(): NotificationActivityService
    {
        return $this->get('notificationActivity');
    }

    /**
     * Returns the notification templates service.
     *
     * @return NotificationTemplateService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getNotificationTemplates(): NotificationTemplateService
    {
        return $this->get('notificationTemplates');
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
     * Returns the registration service.
     *
     * @return RegistrationService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getRegistration(): RegistrationService
    {
        return $this->get('registration');
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
     * Returns the strength service.
     *
     * @return StrengthService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStrength(): StrengthService
    {
        return $this->get('strength');
    }

    /**
     * Returns the user index service.
     *
     * @return UserIndexService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUserIndex(): UserIndexService
    {
        return $this->get('userIndex');
    }

    /**
     * Returns the user state service.
     *
     * @return UserStateService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUserState(): UserStateService
    {
        return $this->get('userState');
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
