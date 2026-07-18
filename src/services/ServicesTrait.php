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
 * @property AlertCooldownService $alertCooldown
 * @property ApiTokenService $apiTokens
 * @property AuditLogService $auditLog
 * @property BlocklistService $blocklist
 * @property ComplianceAggregateService $complianceAggregates
 * @property DeviceLabelService $deviceLabel
 * @property DeviceTrackingService $deviceTracking
 * @property GeoIpService $geoIp
 * @property GovernanceAuditService $governanceAudit
 * @property GroupAlertService $groupAlerts
 * @property HibpClientInterface $hibpClient
 * @property InactiveAccountService $inactiveAccounts
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
 * @property SiemService $siem
 * @property StrengthService $strength
 * @property UserIndexService $userIndex
 * @property UserStateService $userState
 * @property VitePluginService $vite
 * @property WebhookService $webhook
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
                'alertCooldown' => AlertCooldownService::class,
                'apiTokens' => ApiTokenService::class,
                'auditLog' => AuditLogService::class,
                'blocklist' => BlocklistService::class,
                'complianceAggregates' => ComplianceAggregateService::class,
                'deviceLabel' => DeviceLabelService::class,
                'deviceTracking' => DeviceTrackingService::class,
                'geoIp' => GeoIpService::class,
                'governanceAudit' => GovernanceAuditService::class,
                'groupAlerts' => GroupAlertService::class,
                'hibpClient' => GuzzleHibpClient::class,
                'inactiveAccounts' => InactiveAccountService::class,
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
                'siem' => SiemService::class,
                'strength' => StrengthService::class,
                'userIndex' => UserIndexService::class,
                'userState' => UserStateService::class,
                'webhook' => WebhookService::class,
                // Register the vite service
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
     * Returns the alert cooldown service.
     *
     * @return AlertCooldownService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAlertCooldown(): AlertCooldownService
    {
        return $this->get('alertCooldown');
    }

    /**
     * Returns the API token service.
     *
     * Owns the `passwordpolicy_api_tokens` read + write path for Feature 2
     * (the read-only REST surface, Enterprise). Tokens are stored hashed
     * (SHA-256) with a short display prefix; the plaintext is shown once at
     * issue. No edition gate in the service — the gate lives on the CP
     * token manager + the `ApiController` one layer up.
     *
     * @return ApiTokenService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getApiTokens(): ApiTokenService
    {
        return $this->get('apiTokens');
    }

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
     * Returns the compliance-aggregate service (G3 dashboard + reports).
     *
     * Runs read-only aggregates over the Phase G audit infrastructure.
     * Capture is universal across editions; the service does NOT gate on
     * `getIsEnterprise()`. Edition gating lives on the utility +
     * controller surfaces one layer above.
     *
     * @return ComplianceAggregateService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getComplianceAggregates(): ComplianceAggregateService
    {
        return $this->get('complianceAggregates');
    }

    /**
     * Returns the device-label service.
     *
     * Pure transforms — user-agent → human-readable label, raw IP →
     * masked IP. Used by {@see getDeviceTracking()} and the new-device
     * alert wiring. No edition gate (capture is universal).
     *
     * @return DeviceLabelService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getDeviceLabel(): DeviceLabelService
    {
        return $this->get('deviceLabel');
    }

    /**
     * Returns the device-tracking service.
     *
     * Owns the `passwordpolicy_known_devices` write + read path for
     * Feature 1. `recordLogin()` writes on every edition (capture is
     * universal per `project_audit_capture_principle.md`); the
     * new-device alert email + audit exposure are Enterprise-gated one
     * layer up at the listener.
     *
     * @return DeviceTrackingService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getDeviceTracking(): DeviceTrackingService
    {
        return $this->get('deviceTracking');
    }

    /**
     * Returns the IP geolocation service.
     *
     * Resolves IPs to country/region via the bundled DB-IP Lite
     * database. Returns `null` results when `geoIpEnabled` is off. The
     * single entry point for audit enrichment + the new-device label.
     *
     * @return GeoIpService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getGeoIp(): GeoIpService
    {
        return $this->get('geoIp');
    }

    /**
     * Returns the governance-audit emitter — PP's publisher onto the shared
     * Audit Kit bus for named-policy saves/deletes and user-group → policy
     * assignment changes. Emission only; PP registers no recorder sink on the
     * bus (it keeps its own hash-chained log and its Auth Kit sink).
     *
     * @return GovernanceAuditService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getGovernanceAudit(): GovernanceAuditService
    {
        return $this->get('governanceAudit');
    }

    /**
     * Returns the group-alert subscription service.
     *
     * Owns the `passwordpolicy_group_alert_subscriptions` read + write path
     * for Feature 3 (per-group alerts, Pro). `recipientsForUser()` resolves
     * security-contact recipients from the affected user's RESOLVED group
     * set — see `project_per_group_resolution_hazard.md`. Storage is
     * edition-independent; the dispatch that consumes it is Pro-gated one
     * layer up.
     *
     * @return GroupAlertService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getGroupAlerts(): GroupAlertService
    {
        return $this->get('groupAlerts');
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
     * Returns the inactive-account service.
     *
     * Owns the Feature 5 (Pro) detection query + the three action modes
     * (`report` | `notify` | `suspend`). Detection + actions run on Pro;
     * the `account_inactive` audit row is Enterprise-gated inside
     * `applyAction()`.
     *
     * @return InactiveAccountService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getInactiveAccounts(): InactiveAccountService
    {
        return $this->get('inactiveAccounts');
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
     * Returns the SIEM forwarder service.
     *
     * @return SiemService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSiem(): SiemService
    {
        return $this->get('siem');
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

    /**
     * Returns the webhook delivery service.
     *
     * @return WebhookService
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getWebhook(): WebhookService
    {
        return $this->get('webhook');
    }
}
