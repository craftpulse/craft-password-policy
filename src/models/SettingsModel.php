<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use Craft;
use craft\base\Model;
use craft\behaviors\EnvAttributeParserBehavior;

/**
 * Class SettingsModel
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class SettingsModel extends Model
{
    // Public Properties — Lite
    // =========================================================================

    /**
     * @var int the minimum length for the password, can't be lower than 6 (Craft Standard)
     */
    public int $minLength = 6;

    /**
     * @var int the maximum length for the password, it's advised against setting a max length, but could help in cases where users know generated passwords always have a specific length.
     */
    public int $maxLength = 0;

    /**
     * @var bool if the password should contain different cases when chosen
     */
    public bool $cases = false;

    /**
     * @var bool if the password should contain at least 1 number
     */
    public bool $numbers = false;

    /**
     * @var bool if the password should require special characters
     */
    public bool $symbols = false;

    /**
     * @var bool if the password strength indicator should be shown
     */
    public bool $showStrengthIndicator = false;

    /**
     * @var bool if we should check against the "i have been pwned" database
     */
    public bool $pwned = false;

    /**
     * @var string HIBP failure behavior: 'open' accepts password when API unreachable, 'closed' rejects it
     *
     * @since 5.2.0
     */
    public string $pwnedFailMode = 'open';

    /**
     * @var bool if we should show and enable the retention utilities
     */
    public bool $retentionUtilities = false;

    /**
     * @var int|null the expiry amount for the password retention reset period
     */
    public ?int $expiryAmount = null;

    /**
     * @var string the selected retention period value
     */
    public string $expiryPeriod = 'day';

    /**
     * @var bool if csp nonces should be generated
     *
     * @since 5.1.0
     */
    public bool $cspNonce = false;

    /**
     * @var bool whether new users must change their password on first login
     *
     * @since 5.2.0
     */
    public bool $forceChangeOnFirstLogin = false;

    // Public Properties — Pro
    // =========================================================================

    /**
     * @var int the number of previous passwords to check against (0 = disabled, max 24)
     *
     * @since 5.2.0
     */
    public int $passwordHistoryCount = 0;

    /**
     * @var int the number of days to retain password history entries before pruning
     *
     * @since 5.2.0
     */
    public int $passwordHistoryExpiryDays = 365;

    /**
     * @var bool whether to check for sequential character sequences (e.g. abc, 123)
     *
     * @since 5.2.0
     */
    public bool $checkSequentialChars = false;

    /**
     * @var bool whether to check for repeated characters (e.g. aaa, 111)
     *
     * @since 5.2.0
     */
    public bool $checkRepeatedChars = false;

    /**
     * @var bool whether to check password against contextual data (username, email, site name)
     *
     * @since 5.2.0
     */
    public bool $checkContextual = false;

    /**
     * @var bool whether to check password against common password blocklist
     *
     * @since 5.2.0
     */
    public bool $checkCommonPasswords = false;

    /**
     * @var string complexity mode: 'individual' for per-toggle checks, 'minimum' for X-of-4 character types
     *
     * @since 5.2.0
     */
    public string $complexityMode = 'individual';

    /**
     * @var int when complexityMode is 'minimum', requires at least this many of 4 character types (0-4)
     *
     * @since 5.2.0
     */
    public int $minimumCharacterTypes = 0;

    /**
     * @var bool whether per-group password policies are enabled
     *
     * @since 5.2.0
     */
    public bool $enablePerGroupPolicies = false;

    /**
     * @var array|null per-group policy overrides keyed by group UID
     *
     * @since 5.2.0
     */
    public ?array $groupPolicies = null;

    /**
     * @var int the number of days before password expiry to send a reminder notification
     *
     * @since 5.2.0
     */
    public int $expiryReminderDays = 14;

    /**
     * @var int the number of days to retain notification log entries
     *
     * @since 5.2.0
     */
    public int $notificationLogRetentionDays = 30;

    // Public Properties — Enterprise
    // =========================================================================

    /**
     * @var bool whether audit logging is enabled
     *
     * @since 5.2.0
     */
    public bool $enableAuditLog = false;

    /**
     * @var int the number of days to retain audit log entries
     *
     * @since 5.2.0
     */
    public int $auditLogRetentionDays = 365;

    /**
     * @var bool whether login anomaly detection with new device alerts is enabled
     *
     * @since 5.2.0
     */
    public bool $enableNewDeviceAlerts = false;

    /**
     * @var int the number of days to retain known device records
     *
     * @since 5.2.0
     */
    public int $deviceRetentionDays = 180;

    /**
     * @var string|null the email address for admin security alerts (supports env vars)
     *
     * @since 5.2.0
     */
    public ?string $adminAlertEmail = null;

    /**
     * @var array|null the audit events that trigger admin alerts
     *
     * @since 5.2.0
     */
    public ?array $adminAlertEvents = null;

    /**
     * @var bool whether SIEM forwarding is enabled
     *
     * @since 5.2.0
     */
    public bool $siemEnabled = false;

    /**
     * @var string SIEM destination type: 'syslog', 'http', or 'event'
     *
     * @since 5.2.0
     */
    public string $siemDestinationType = 'syslog';

    /**
     * @var string|null SIEM HTTP endpoint URL (supports env vars)
     *
     * @since 5.2.0
     */
    public ?string $siemEndpointUrl = null;

    /**
     * @var string SIEM authentication type: 'bearer', 'basic', or 'header'
     *
     * @since 5.2.0
     */
    public string $siemAuthType = 'bearer';

    /**
     * @var string|null SIEM authentication token (supports env vars, never shown after save)
     *
     * @since 5.2.0
     */
    public ?string $siemAuthToken = null;

    /**
     * @var array|null custom SIEM HTTP headers
     *
     * @since 5.2.0
     */
    public ?array $siemCustomHeaders = null;

    /**
     * @var string how IP addresses are included in SIEM payloads: 'masked', 'hashed', 'raw', or 'excluded'
     *
     * @since 5.2.0
     */
    public string $siemIpHandling = 'masked';

    /**
     * @var string how device info is included in SIEM payloads: 'label' or 'excluded'
     *
     * @since 5.2.0
     */
    public string $siemDeviceHandling = 'label';

    /**
     * @var bool whether webhook events are enabled
     *
     * @since 5.2.0
     */
    public bool $webhooksEnabled = false;

    /**
     * @var array registered webhook configurations
     *
     * @since 5.2.0
     */
    public array $webhooks = [];

    /**
     * @var bool whether the API token management system is enabled
     *
     * @since 5.2.0
     */
    public bool $apiEnabled = false;

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    protected function defineBehaviors(): array
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => [
                    'minLength',
                    'maxLength',
                    'adminAlertEmail',
                    'siemEndpointUrl',
                    'siemAuthToken',
                ],
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    protected function defineRules(): array
    {
        return array_merge(parent::defineRules(), [
            // Length rules
            [['minLength'], 'required'],
            [
                ['minLength'],
                'number',
                'integerOnly' => true,
                'min' => 6,
                'message' => Craft::t('password-policy', 'The minimum length can not be less than 6.'),
            ],
            [
                ['maxLength'],
                'number',
                'integerOnly' => true,
                'min' => 6,
                'message' => Craft::t('password-policy', 'The minimum length can not be less than 6.'),
                'when' => function($setting) {
                    return $setting->maxLength > 0;
                },
            ],
            [
                ['maxLength'],
                'compare',
                'compareAttribute' => 'minLength',
                'operator' => '>=',
                'message' => Craft::t('password-policy', 'The minimum length must be less than or equal to the maximum length.'),
                'when' => function($setting) {
                    return $setting->maxLength > 0;
                },
            ],

            // Period rules
            [
                ['expiryPeriod'],
                'in',
                'range' => ['day', 'week', 'month', 'year'],
                'message' => Craft::t('password-policy', 'The selected expiry period is invalid.'),
            ],

            // Boolean rules
            [
                [
                    'cases',
                    'cspNonce',
                    'numbers',
                    'symbols',
                    'retentionUtilities',
                    'showStrengthIndicator',
                    'pwned',
                    'forceChangeOnFirstLogin',
                    'checkSequentialChars',
                    'checkRepeatedChars',
                    'checkContextual',
                    'checkCommonPasswords',
                    'enablePerGroupPolicies',
                    'enableAuditLog',
                    'enableNewDeviceAlerts',
                    'siemEnabled',
                    'webhooksEnabled',
                    'apiEnabled',
                ],
                'boolean',
            ],

            // Enum rules
            [
                ['pwnedFailMode'],
                'in',
                'range' => ['open', 'closed'],
                'message' => Craft::t('password-policy', 'The HIBP fail mode must be either "open" or "closed".'),
            ],
            [
                ['complexityMode'],
                'in',
                'range' => ['individual', 'minimum'],
                'message' => Craft::t('password-policy', 'The complexity mode must be either "individual" or "minimum".'),
            ],
            [
                ['siemDestinationType'],
                'in',
                'range' => ['syslog', 'http', 'event'],
                'message' => Craft::t('password-policy', 'The SIEM destination type is invalid.'),
            ],
            [
                ['siemAuthType'],
                'in',
                'range' => ['bearer', 'basic', 'header'],
                'message' => Craft::t('password-policy', 'The SIEM auth type is invalid.'),
            ],
            [
                ['siemIpHandling'],
                'in',
                'range' => ['masked', 'hashed', 'raw', 'excluded'],
                'message' => Craft::t('password-policy', 'The SIEM IP handling mode is invalid.'),
            ],
            [
                ['siemDeviceHandling'],
                'in',
                'range' => ['label', 'excluded'],
                'message' => Craft::t('password-policy', 'The SIEM device handling mode is invalid.'),
            ],

            // Integer rules
            [
                ['passwordHistoryCount'],
                'number',
                'integerOnly' => true,
                'min' => 0,
                'max' => 24,
                'message' => Craft::t('password-policy', 'Password history count must be between 0 and 24.'),
            ],
            [
                ['minimumCharacterTypes'],
                'number',
                'integerOnly' => true,
                'min' => 0,
                'max' => 4,
                'message' => Craft::t('password-policy', 'Minimum character types must be between 0 and 4.'),
            ],
            [
                ['passwordHistoryExpiryDays'],
                'number',
                'integerOnly' => true,
                'min' => 1,
                'message' => Craft::t('password-policy', 'Password history expiry must be at least 1 day.'),
            ],
            [
                ['auditLogRetentionDays'],
                'number',
                'integerOnly' => true,
                'min' => 1,
                'message' => Craft::t('password-policy', 'Audit log retention must be at least 1 day.'),
            ],
            [
                ['deviceRetentionDays'],
                'number',
                'integerOnly' => true,
                'min' => 1,
                'message' => Craft::t('password-policy', 'Device retention must be at least 1 day.'),
            ],
            [
                ['notificationLogRetentionDays'],
                'number',
                'integerOnly' => true,
                'min' => 1,
                'message' => Craft::t('password-policy', 'Notification log retention must be at least 1 day.'),
            ],
            [
                ['expiryReminderDays'],
                'number',
                'integerOnly' => true,
                'min' => 1,
                'message' => Craft::t('password-policy', 'Expiry reminder must be at least 1 day.'),
            ],
        ]);
    }
}
