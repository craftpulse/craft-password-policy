<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy;

use Craft;
use craft\base\Element;
use craft\base\Model;
use craft\base\Plugin;
use craft\controllers\UsersController;
use craft\elements\conditions\users\UserCondition;
use craft\elements\User;
use craft\enums\CmsEdition;
use craft\events\AuthenticateUserEvent;
use craft\events\DefineAttributeHtmlEvent;
use craft\events\DefineEditUserScreensEvent;
use craft\events\DefineMenuItemsEvent;
use craft\events\DefineRulesEvent;
use craft\events\ModelEvent;
use craft\events\RegisterComponentTypesEvent;
use craft\events\RegisterConditionRulesEvent;
use craft\events\RegisterElementActionsEvent;
use craft\events\RegisterElementSortOptionsEvent;
use craft\events\RegisterElementTableAttributesEvent;
use craft\events\RegisterEmailMessagesEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\events\RegisterUserPermissionsEvent;
use craft\events\SiteEvent;
use craft\events\TemplateEvent;
use craft\events\UserEvent;
use craft\events\UserGroupEvent;
use craft\helpers\ArrayHelper;
use craft\helpers\ElementHelper;
use craft\helpers\Json;
use craft\helpers\UrlHelper;
use craft\log\MonologTarget;
use craft\services\Elements;
use craft\services\Gc;
use craft\services\Sites;
use craft\services\SystemMessages;
use craft\services\UserGroups;
use craft\services\UserPermissions;
use craft\services\Users;
use craft\services\Utilities;
use craft\web\Application;
use craft\web\twig\variables\CraftVariable;
use craft\web\UrlManager;
use craft\web\View;
use craftpulse\passwordpolicy\assetbundles\passwordpolicy\PasswordPolicyAsset;
use craftpulse\passwordpolicy\controllers\UserSecurityController;
use craftpulse\passwordpolicy\elements\actions\ChangeUserPassword;
use craftpulse\passwordpolicy\elements\actions\ForcePasswordReset;
use craftpulse\passwordpolicy\elements\actions\SendPasswordResetEmail;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\elements\conditions\BreachedRecentlyConditionRule;
use craftpulse\passwordpolicy\elements\conditions\LastChangeReasonConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordExpiredConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordExpiringWithinConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordNeverChangedConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordResetRequiredConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordStatusConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PolicyDriftConditionRule;
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\elements\PolicyElement;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\events\BreachDetectedEvent;
use craftpulse\passwordpolicy\events\GroupAlertDispatchedEvent;
use craftpulse\passwordpolicy\events\NewDeviceDetectedEvent;
use craftpulse\passwordpolicy\events\PasswordChangedEvent;
use craftpulse\passwordpolicy\events\PasswordValidationEvent;
use craftpulse\passwordpolicy\models\AuditContext;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\rules\UserRules;
use craftpulse\passwordpolicy\services\AlertCooldownService;
use craftpulse\passwordpolicy\services\ServicesTrait;
use craftpulse\passwordpolicy\utilities\AuditExportUtility;
use craftpulse\passwordpolicy\utilities\AuditSchemaUtility;
use craftpulse\passwordpolicy\utilities\ComplianceDashboardUtility;
use craftpulse\passwordpolicy\utilities\RetentionUtility;
use craftpulse\passwordpolicy\variables\PasswordPolicyVariable;
use Monolog\Formatter\LineFormatter;
use Psr\Log\LogLevel;
use Throwable;
use yii\base\Event;
use yii\base\InvalidConfigException;
use yii\base\InvalidRouteException;
use yii\log\Dispatcher;
use yii\log\Logger;
use yii\web\User as WebUser;
use yii\web\UserEvent as WebUserEvent;

/**
 * Class PasswordPolicy
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 *
 * @method SettingsModel getSettings()
 */
class PasswordPolicy extends Plugin
{
    // Traits
    // =========================================================================

    use ServicesTrait;

    // Const Properties
    // =========================================================================

    /**
     * @var string
     */
    public const EDITION_LITE = 'lite';

    /**
     * @var string
     */
    public const EDITION_PRO = 'pro';

    /**
     * @var string
     */
    public const EDITION_ENTERPRISE = 'enterprise';

    /**
     * Fired after a password has been changed and stored in history.
     * The plaintext is already gone by this point.
     *
     * @event PasswordChangedEvent
     *
     * @since 5.2.0
     */
    public const EVENT_PASSWORD_CHANGED = 'passwordChanged';

    /**
     * Fired by the HIBP-on-login Pro listener when a user's plaintext password
     * matches a SHA-1 prefix bucket on the HIBP API. The plaintext, full hash,
     * and bucket suffix are intentionally NOT in the event payload — see
     * BreachDetectedEvent class docblock.
     *
     * @event BreachDetectedEvent
     *
     * @since 5.2.0
     */
    public const EVENT_BREACH_DETECTED = 'breachDetected';

    /**
     * Fired by the Feature 1 login listener after a login from a device
     * fingerprint with no prior row for the user — i.e. after the
     * `passwordpolicy_known_devices` row is written. Fires on EVERY
     * edition (free ecosystem hook; capture is universal per
     * `project_audit_capture_principle.md`), independent of whether the
     * Enterprise-gated new-device alert email is sent.
     *
     * The payload carries only the masked IP + human-readable device
     * label — never the raw user-agent, raw IP, or the fingerprint. See
     * {@see NewDeviceDetectedEvent} class docblock.
     *
     * @event NewDeviceDetectedEvent
     *
     * @since 5.2.0
     */
    public const EVENT_NEW_DEVICE_DETECTED = 'newDeviceDetected';

    /**
     * Fired by the Feature 3 per-group alert routing (Pro) after a COPY of
     * a `breach_detected` / `new_device` alert is dispatched to a
     * group-designated security contact — once per recipient that cleared
     * the per-group cooldown. Does NOT fire for the end-user's own alert,
     * nor for recipients suppressed by the cooldown.
     *
     * Fires only on Pro (or higher) — per-group alerts are a Pro surface.
     * The payload carries the affected user, the resolving `groupId`, the
     * `eventType`, and the `recipientEmail` — never password material. See
     * {@see GroupAlertDispatchedEvent} class docblock.
     *
     * @event GroupAlertDispatchedEvent
     *
     * @since 5.2.0
     */
    public const EVENT_GROUP_ALERT_DISPATCHED = 'groupAlertDispatched';

    /**
     * Fired after the plugin's password rules have run on a User during
     * `Model::validate()` and the aggregated outcome is known. Listeners
     * receive the validating User, the password-specific errors collected
     * by the plugin's rule set, and the boolean validity flag — third-
     * party modules use this seam to add their own validation logic
     * (custom dictionary checks, attribute-derived blocklisting, etc.).
     *
     * The plaintext password and any derived hash material are
     * intentionally NOT in the event payload — see PasswordValidationEvent
     * class docblock.
     *
     * @event PasswordValidationEvent
     *
     * @since 5.2.0
     */
    public const EVENT_PASSWORD_VALIDATION = 'passwordValidation';

    /**
     * Sensitive keys that must never appear in log output.
     *
     * @var string[]
     */
    private const SENSITIVE_LOG_KEYS = [
        'password',
        'newPassword',
        'plaintext',
        'hash',
        'passwordHash',
    ];

    // Static Properties
    // =========================================================================

    /**
     * @var ?PasswordPolicy
     */
    public static ?PasswordPolicy $plugin = null;

    // Private Properties
    // =========================================================================

    /**
     * Guard to prevent infinite recursion when setting passwordResetRequired
     * inside EVENT_AFTER_SAVE triggers another save cycle.
     *
     * @var array<int, bool>
     */
    private static array $_processing = [];

    // Static Methods
    // =========================================================================

    /**
     * Returns the available editions for this plugin.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function editions(): array
    {
        return [
            self::EDITION_LITE,
            self::EDITION_PRO,
            self::EDITION_ENTERPRISE,
        ];
    }

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public string $schemaVersion = '2.15.0';

    /**
     * @var bool
     */
    public bool $hasCpSection = true;

    /**
     * @var bool
     */
    public bool $hasCpSettings = true;

    /**
     * @var ?object
     */
    public ?object $queue = null;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     */
    public function init(): void
    {
        parent::init();
        self::$plugin = $this;

        // Register custom log target
        $this->_registerLogTarget();

        $request = Craft::$app->getRequest();
        if ($request->getIsConsoleRequest()) {
            $this->controllerNamespace = 'craftpulse\passwordpolicy\console\controllers';
        }

        // Install our global event handlers
        $this->_installEventHandlers();

        // Register control panel events
        if (Craft::$app->getRequest()->getIsCpRequest()) {
            $this->_registerCpUrlRules();
            $this->_installCpEventHandlers();
        }

        // Log that the plugin has loaded
        Craft::info(
            Craft::t(
                'password-policy',
                '{name} plugin loaded',
                ['name' => $this->name]
            )
        );
    }

    /**
     * Logs a message.
     *
     * @param string $message
     * @param array $params
     * @param int $type
     * @return void
     *
     * @throws Throwable
     *
     * @author CraftPulse
     */
    public function log(string $message, array $params = [], int $type = Logger::LEVEL_INFO): void
    {
        // Strip sensitive keys before any logging occurs
        $params = array_diff_key($params, array_flip(self::SENSITIVE_LOG_KEYS));

        /** @var User|null $user */
        $user = Craft::$app->getUser()->getIdentity();

        if ($user !== null) {
            $params['username'] = $user->username;
        }

        // Encode with unescaped slashes/unicode so the log line stays
        // readable. The previous `str_replace('\\', '', …)` mangled any
        // namespaced class name or Windows path in the payload by stripping
        // every backslash — the JSON flags solve the readability goal
        // without corrupting legitimate backslashes.
        $encoded_params = Json::encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $message = Craft::t('password-policy', $message . ' ' . $encoded_params, $params);

        Craft::getLogger()->log($message, $type, 'password-policy');
    }

    /**
     * Runs garbage collection on all retention-managed plugin tables.
     *
     * Single source of truth shared by the deterministic
     * `password-policy/gc/run` console command and the probabilistic Craft
     * `Gc::EVENT_RUN` listener. Adding a new retention table only requires
     * updating this method.
     *
     * @return array<string, int> map of table key → purged row count.
     *     Only tables that actually ran are included; skipped tables
     *     (wrong edition, feature disabled, count floor zero) are absent.
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function runGc(): array
    {
        $settings = $this->getSettings();
        $results = [];

        if ($settings->passwordHistoryCount > 0) {
            $results['passwordHistory'] = $this->getPasswordHistory()->purgeExpiredHistory(
                $settings->passwordHistoryExpiryDays,
                $settings->passwordHistoryCount,
            );
        }

        // Notification log pruning runs on every edition — capture is
        // edition-agnostic (admin_alert_* paths fire on Lite too) so
        // the retention cleanup must match. Gating to Pro here would
        // let Lite installs grow the log table unbounded. Architectural
        // invariant: capture everywhere, gate exposure (the Activity
        // CP screen) — see `project_audit_capture_principle.md`.
        $results['notificationLog'] = $this->getNotification()->pruneOldEntries(
            $settings->notificationLogRetentionDays,
        );

        // Audit log pruning runs on every edition for the same reason
        // notification log pruning does (above): G1 made audit capture
        // universal, so prune must match. Gating to Enterprise would
        // let Lite/Pro installs grow the table unbounded after they've
        // written `password_changed` / `account_locked` /
        // `account_unlocked` rows. The `enableAuditLog` admin toggle is
        // unchecked here on purpose — pruning a table that's not being
        // written to is a no-op DELETE. Same architectural invariant:
        // capture everywhere, gate exposure (the verifier CLI / dashboard
        // / forwarder) — see `project_audit_capture_principle.md`.
        $results['auditLog'] = $this->getAuditLog()->purgeOldEntries(
            $settings->auditLogRetentionDays,
        );

        // Alert cooldown pruning (G7) — universal capture, same reason
        // as the audit + notification log prunes above. The service
        // computes its own threshold from the longest configured
        // cooldown OR a 7-day floor so the auditor's "show me last
        // week's suppression record" query never comes up empty due
        // to over-aggressive prune.
        $results['alertCooldowns'] = $this->getAlertCooldown()->pruneOldEntries();

        // Known-device pruning (Feature 1) — universal capture, same
        // reasoning as the prunes above. Device rows are written on every
        // edition; without a periodic prune the table grows unbounded.
        // `pruneOldDevices()` treats a non-positive retention window as a
        // no-op, so a misconfigured `deviceRetentionDays` never wipes the
        // table.
        $results['knownDevices'] = $this->getDeviceTracking()->pruneOldDevices(
            $settings->deviceRetentionDays,
        );

        return $results;
    }

    /**
     * Returns whether the plugin is running the Lite edition.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsLite(): bool
    {
        return $this->is(self::EDITION_LITE);
    }

    /**
     * Returns whether the plugin is running the Pro edition or higher.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsPro(): bool
    {
        return $this->is(self::EDITION_PRO, '>=');
    }

    /**
     * Returns whether the plugin is running the Enterprise edition.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsEnterprise(): bool
    {
        return $this->is(self::EDITION_ENTERPRISE);
    }

    /**
     * Returns whether the host Craft install is on the Solo edition.
     *
     * Solo caps multi-user features that two of D2's user-index columns
     * (policy drift + applied policies) and one condition rule depend on
     * — namely user groups and per-group policy resolution. The plugin
     * gate (`getIsPro()`) handles its own edition; this gate handles the
     * underlying Craft license. Both must clear before the gated affordance
     * registers.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isCraftSolo(): bool
    {
        return Craft::$app->edition === CmsEdition::Solo;
    }

    /**
     * Returns whether the host Craft install is on the Team edition or
     * higher (Team, Pro, Enterprise). Convenience inverse of
     * {@see self::isCraftSolo()}.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isCraftTeamOrBetter(): bool
    {
        return Craft::$app->edition->value >= CmsEdition::Team->value;
    }

    /**
     * @inheritdoc
     *
     * @throws InvalidRouteException
     *
     * @author CraftPulse
     */
    public function getSettingsResponse(): mixed
    {
        return Craft::$app->getResponse()->redirect('password-policy/settings');
    }

    /**
     * @inheritdoc
     *
     * **Performance contract:** this method runs on every CP page
     * render — every page, every user. Badge counts and conditional
     * visibility checks must come from cached or indexed-scalar
     * sources. **No element queries, no aggregate queries without
     * caching.** A 5-minute cache is the floor for any badge derived
     * from a `COUNT(*)`. The current method body only reads settings
     * + permission checks, both of which are sub-millisecond; preserve
     * that ceiling when adding subnav items.
     *
     * @throws Throwable
     *
     * @author CraftPulse
     */
    public function getCpNavItem(): ?array
    {
        $subNavs = [];
        $navItem = parent::getCpNavItem();
        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser === null) {
            return null;
        }

        // Named policies subnav (Pro + per-group enabled) — listed first
        if ($this->getIsPro() && $currentUser->can('pp:settings')) {
            $settings = $this->getSettings();
            if ($settings->enablePerGroupPolicies) {
                $subNavs['policies'] = [
                    'label' => Craft::t('password-policy', 'Policies'),
                    'url' => 'password-policy/policies',
                ];
            }
        }

        // Blocklist subnav (Pro) — sits between Policies and Settings.
        // Lite users don't see it (no editable feature behind it); discovery
        // happens via plugin docs / marketing.
        if ($this->getIsPro() && $currentUser->can('pp:blocklist-view')) {
            $subNavs['blocklist'] = [
                'label' => Craft::t('password-policy', 'Blocklist'),
                'url' => 'password-policy/blocklist',
            ];
        }

        // Notifications subnav (Pro) — sits between Blocklist and Settings.
        // Activity is a sibling entry (matches Formie's "Email Templates" /
        // "Sent Notifications" split) — separate page for delivery /
        // failure history that ops want to land on directly without an
        // extra click through Templates.
        //
        // The two subnavs gate on DIFFERENT permissions since P3-10:
        //  - Notifications (template editor) → `pp:notification-
        //    templates-manage` (write surface, edit per-(key, site)
        //    templates).
        //  - Activity (delivery log reader) → `pp:notification-log-
        //    view` (audit-read surface). Template-manage also grants
        //    activity view since an admin editing templates needs to
        //    see how they perform; reverse not implied (an auditor
        //    can read activity without editing).
        if ($this->getIsPro() && $currentUser->can('pp:notification-templates-manage')) {
            $subNavs['notifications'] = [
                'label' => Craft::t('password-policy', 'Notifications'),
                'url' => 'password-policy/notifications',
            ];
        }

        if (
            $this->getIsPro()
            && (
                $currentUser->can('pp:notification-log-view')
                || $currentUser->can('pp:notification-templates-manage')
            )
        ) {
            $subNavs['notification-activity'] = [
                'label' => Craft::t('password-policy', 'Activity'),
                'url' => 'password-policy/notifications/activity',
            ];
        }

        // Group alerts subnav (Pro) — Feature 3 per-group alert routing.
        // Reuses `pp:notification-templates-manage`: configuring which
        // security contact gets a copy of which alert is a
        // notification-management concern, so it sits behind the same
        // permission that gates the template editor in this neighborhood.
        if ($this->getIsPro() && $currentUser->can('pp:notification-templates-manage')) {
            $subNavs['group-alerts'] = [
                'label' => Craft::t('password-policy', 'Group alerts'),
                'url' => 'password-policy/notifications/group-alerts',
            ];
        }

        // SIEM forwarders subnav (Enterprise) — sits between Notifications
        // and Settings. Forwarders are a delivery channel for the audit
        // log; placing them under the Notifications neighborhood matches
        // the operator's mental model of "where do delivery configs
        // live?" Edition + permission gated; both must clear before the
        // entry registers.
        if ($this->getIsEnterprise() && $currentUser->can('pp:siem-manage')) {
            $subNavs['siem-forwarders'] = [
                'label' => Craft::t('password-policy', 'SIEM forwarders'),
                'url' => 'password-policy/siem',
            ];
        }

        // Webhooks subnav (Enterprise) — sits next to SIEM. Webhooks
        // are the second audit-log delivery channel; same edition +
        // permission gate, parallel surface.
        if ($this->getIsEnterprise() && $currentUser->can('pp:webhooks-manage')) {
            $subNavs['webhooks'] = [
                'label' => Craft::t('password-policy', 'Webhooks'),
                'url' => 'password-policy/webhooks',
            ];
        }

        // Settings visible in read-only mode too (admins can view active policy)
        if ($currentUser->can('pp:settings')) {
            $subNavs['settings'] = [
                'label' => Craft::t('password-policy', 'Settings'),
                'url' => 'password-policy/settings',
            ];
        }

        if (empty($subNavs)) {
            return null;
        }

        // A single sub nav item is redundant
        if (count($subNavs) === 1) {
            $subNavs = [];
        }

        return array_merge($navItem, [
            'subnav' => $subNavs,
        ]);
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    protected function settingsHtml(): ?string
    {
        return Craft::$app->getView()->renderTemplate(
            'password-policy/_settings',
            ['settings' => $this->getSettings()]
        );
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    protected function createSettingsModel(): ?Model
    {
        return new SettingsModel();
    }

    // Private Methods
    // =========================================================================

    /**
     * Installs global event handlers.
     *
     * @return void
     *
     * @author CraftPulse
     */
    private function _installEventHandlers(): void
    {
        Event::on(
            CraftVariable::class,
            CraftVariable::EVENT_INIT,
            function(Event $event) {
                /** @var CraftVariable $variable */
                $variable = $event->sender;

                $config = [
                    'class' => PasswordPolicyVariable::class,
                    'viteService' => $this->vite,
                ];

                // Register under both handles. `passwordpolicy` (lowercase)
                // shipped in 5.1.1 and stays valid permanently for backward
                // compatibility — never @deprecated. `passwordPolicy`
                // (camelCase) is the canonical form going forward, matches
                // modern Craft convention, and is what the C2 docs use.
                $variable->set('passwordpolicy', $config);
                $variable->set('passwordPolicy', $config);
            }
        );

        Event::on(
            User::class,
            User::EVENT_DEFINE_RULES,
            static function(DefineRulesEvent $event) {
                $event->rules = ArrayHelper::where($event->rules, function($rule) {
                    $attributes = is_array($rule[0] ?? null) ? $rule[0] : [$rule[0] ?? null];
                    return !array_intersect($attributes, ['password', 'newPassword']);
                });

                /** @var User $user */
                $user = $event->sender;

                foreach (UserRules::defineRules($user) as $rule) {
                    $event->rules[] = $rule;
                }
            }
        );

        // Fire the developer-facing `PasswordValidationEvent` once Yii's
        // `validate()` has run all rules on the User. The listener pulls
        // the password-attribute errors out of the User, packs them into
        // the event payload, and triggers — third-party modules use this
        // seam to add their own validation logic (custom dictionary
        // checks, attribute-derived blocklisting, etc.). Listeners can
        // also push back onto `$event->user->addError(...)` if they want
        // their custom errors to surface in the user-facing form
        // response — `$event->errors` is a snapshot of the plugin's own
        // rule outcome at the time of firing.
        $this->_registerPasswordValidationEvent();

        // Password history: cache plaintext before save
        $this->_registerPasswordHistoryListeners();

        // Craft security event listeners (Enterprise audit logging)
        $this->_registerCraftSecurityListeners();

        // Observability seam for policy assignments dropped via group deletion
        $this->_registerUserGroupListeners();

        // Notification template propagation when a new site is added
        $this->_registerSiteListeners();

        // HIBP-on-login (Pro) — re-checks the plaintext during BEFORE_AUTHENTICATE
        if ($this->getIsPro()) {
            $this->_registerHibpOnLoginListener();
        }

        // Device tracking — records the device on every successful login,
        // on EVERY edition (capture is universal). The new-device alert
        // email + audit exposure are Enterprise-gated inside the listener.
        $this->_registerNewDeviceListener();

        // Safety net: clear any remaining cached passwords at end of request
        $this->_registerRequestCleanup();

        $this->_registerElementTypes();
        $this->_registerUserPermissions();
        $this->_registerUtilities();
        $this->_registerUserIndexIntegration();
        $this->_registerUserEditScreen();
        $this->_registerUserEditActionMenu();
        $this->_registerGarbageCollection();
        $this->_registerSystemMessages();
    }

    /**
     * Installs control panel event handlers.
     *
     * @return void
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     */
    private function _installCpEventHandlers(): void
    {
        // Load asset before page template is rendered
        Event::on(
            View::class,
            View::EVENT_BEFORE_RENDER_PAGE_TEMPLATE,
            function(TemplateEvent $event) {
                // Get view
                $view = Craft::$app->getView();

                // Register Asset Bundle
                $view->registerAssetBundle(PasswordPolicyAsset::class);
                $options = $this->getSettings()->cspNonce ? ['nonce' => $this->getSecurity()->getNonce()] : [];

                $this->vite->register('src/js/indicator.ts', false, $options);
            }
        );
    }

    /**
     * Registers CP URL rules.
     *
     * @return void
     *
     * @author CraftPulse
     */
    private function _registerCpUrlRules(): void
    {
        Event::on(UrlManager::class, UrlManager::EVENT_REGISTER_CP_URL_RULES,
            function(RegisterUrlRulesEvent $event) {
                // Merge so that settings controller action comes first (important!)
                $event->rules = array_merge(
                    [
                        'password-policy' => 'password-policy/settings/edit',
                        'password-policy/settings' => 'password-policy/settings/edit',
                        'password-policy/settings/<section:{slug}>' => 'password-policy/settings/edit',
                        'password-policy/plugins/password-policy' => 'password-policy/settings/edit',
                        'password-policy/policies' => 'password-policy/policy/index',
                        'password-policy/policies/new' => 'password-policy/policy/edit',
                        'password-policy/policies/<policyId:\d+>' => 'password-policy/policy/edit',
                        'password-policy/blocklist' => 'password-policy/blocklist/index',
                        'password-policy/notifications' => 'password-policy/notification-template/index',
                        'password-policy/notifications/activity' => 'password-policy/notification-activity/index',
                        'password-policy/notifications/activity/<id:\d+>' => 'password-policy/notification-activity/view',
                        'password-policy/notifications/activity/resend' => 'password-policy/notification-activity/resend',
                        // Group-alert editor — registered BEFORE the
                        // `<key:[\w\-]+>` catch-all below, which would
                        // otherwise route `group-alerts` to the template
                        // editor.
                        'password-policy/notifications/group-alerts' => 'password-policy/group-alert/index',
                        'password-policy/notifications/group-alerts/save' => 'password-policy/group-alert/save',
                        'password-policy/notifications/<key:[\w\-]+>' => 'password-policy/notification-template/edit',
                        'password-policy/notifications/<key:[\w\-]+>/save' => 'password-policy/notification-template/save',
                        'password-policy/notifications/<key:[\w\-]+>/test-send' => 'password-policy/notification-template/test-send',
                        'password-policy/siem' => 'password-policy/siem-forwarder/index',
                        'password-policy/siem/new' => 'password-policy/siem-forwarder/edit',
                        'password-policy/siem/<forwarderId:\d+>' => 'password-policy/siem-forwarder/edit',
                        'password-policy/webhooks' => 'password-policy/webhook-endpoint/index',
                        'password-policy/webhooks/new' => 'password-policy/webhook-endpoint/edit',
                        'password-policy/webhooks/<endpointId:\d+>' => 'password-policy/webhook-endpoint/edit',
                        'password-policy/audit-export/export' => 'password-policy/audit-export/export',
                        'password-policy/audit-export/download/<token:[A-Za-z0-9_\-]+>' => 'password-policy/audit-export/download',
                        // G3 compliance reports. The URL path uses plural
                        // `/reports/...`; the rewrite target uses the
                        // singular `report` controller-id per Yii's
                        // action-name mapping (Craft routes
                        // `kebab-case` → `actionCamelCase`).
                        'password-policy/reports/<report:[\w\-]+>/html' => 'password-policy/report/html',
                        'password-policy/reports/<report:[\w\-]+>/csv' => 'password-policy/report/csv',
                        'password-policy/user-password/change' => 'password-policy/user-password/change',
                        'password-policy/user-password/send-reset-email' => 'password-policy/user-password/send-reset-email',
                        'password-policy/users/<userId:\d+>/security' => 'password-policy/user-security/index',
                        'password-policy/validate' => 'password-policy/validation/validate',
                    ],
                    $event->rules
                );
            }
        );
    }

    /**
     * Registers user permissions.
     *
     * @return void
     *
     * @author CraftPulse
     */
    private function _registerUserPermissions(): void
    {
        Event::on(UserPermissions::class, UserPermissions::EVENT_REGISTER_PERMISSIONS,
            function(RegisterUserPermissionsEvent $event) {
                $permissions = [
                    'pp:settings' => [
                        'label' => Craft::t('password-policy', 'Manage plugin settings.'),
                    ],
                    'pp:force-reset-passwords' => [
                        'label' => Craft::t('password-policy', 'Force reset passwords retention access.'),
                    ],
                    'pp:change-user-passwords' => [
                        'label' => Craft::t(
                            'password-policy',
                            'Change another user’s password and send password reset emails.',
                        ),
                    ],
                    'pp:blocklist-view' => [
                        'label' => Craft::t('password-policy', 'View password blocklist.'),
                        'nested' => [
                            'pp:blocklist-manage' => [
                                'label' => Craft::t('password-policy', 'Manage password blocklist.'),
                            ],
                        ],
                    ],
                    'pp:notification-templates-manage' => [
                        'label' => Craft::t('password-policy', 'Manage email notification templates.'),
                    ],
                    'pp:notification-log-view' => [
                        'label' => Craft::t(
                            'password-policy',
                            'View the notification activity log (delivery history, errors). Auditor-grantable without template-edit rights.',
                        ),
                    ],
                    'pp:audit-view' => [
                        'label' => Craft::t(
                            'password-policy',
                            'View audit log entries and the per-event PII allowlist registry. Auditor-grantable without full admin.',
                        ),
                    ],
                    'pp:audit-verify' => [
                        'label' => Craft::t(
                            'password-policy',
                            'Run the audit-log verifier CLI. Auditor-grantable without full admin.',
                        ),
                    ],
                ];

                // SIEM forwarder management is an Enterprise-only write
                // surface. Edition-gate at registration so a Pro or
                // Lite admin's permissions screen never lists a
                // permission they can't usefully grant. Top-level
                // (not nested) — SIEM management is independent of
                // `pp:audit-view`'s read surface.
                if ($this->getIsEnterprise()) {
                    $permissions['pp:siem-manage'] = [
                        'label' => Craft::t(
                            'password-policy',
                            'Manage SIEM forwarders for audit-log delivery.',
                        ),
                    ];

                    // Webhook endpoints are an Enterprise-only write
                    // surface, parallel to (not nested under) the SIEM
                    // forwarder permission. Webhooks and SIEM are
                    // independent delivery channels — operators may
                    // run one or both — so the permissions split
                    // separately.
                    $permissions['pp:webhooks-manage'] = [
                        'label' => Craft::t(
                            'password-policy',
                            'Manage HTTP webhook endpoints for audit-log delivery.',
                        ),
                    ];

                    // Audit-log export is an Enterprise-only write-side
                    // privilege — produces durable artifacts capable of
                    // leaving the host (operators download to forward
                    // off-site to evidence systems). Top-level (NOT
                    // nested under `pp:audit-view`) — read access is a
                    // separate decision from the bulk-export decision,
                    // and an auditor with `pp:audit-view` shouldn't be
                    // able to dump the whole table without an explicit
                    // additional grant.
                    $permissions['pp:audit-export'] = [
                        'label' => Craft::t(
                            'password-policy',
                            'Trigger audit-log exports (CP utility + CLI). Produces a downloadable file capable of leaving the host — separate from view access.',
                        ),
                    ];
                }

                $event->permissions[] = [
                    'heading' => 'Password Policy',
                    'permissions' => $permissions,
                ];
            }
        );
    }

    /**
     * Registers plugin-owned element types with Craft.
     *
     * Both `NotificationLogElement` (Step 4) and `AuditLogElement`
     * (Step 5) are universal capture — rows are written on every
     * edition. Edition gates apply to the CP nav surfaces (activity
     * subnav, G3 compliance dashboard) downstream of the element-type
     * registration, never to the underlying writes. Registering on
     * every edition lets fixtures / Pest / console tooling query the
     * element types even on Lite installs.
     *
     * `AuditLogElement` is registered so `AuditLogElement::find()`
     * resolves and Craft knows about the type for element-id collision
     * checks, soft-delete bookkeeping, and the future G3 dashboard.
     * Step 5 deliberately does NOT add a top-level "Audit Log" CP
     * subnav — that's G3's job — but the type is available to anyone
     * who wants to query it via the element API.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerElementTypes(): void
    {
        Event::on(
            Elements::class,
            Elements::EVENT_REGISTER_ELEMENT_TYPES,
            static function(RegisterComponentTypesEvent $event) {
                $event->types[] = NotificationLogElement::class;
                $event->types[] = AuditLogElement::class;
                $event->types[] = PolicyElement::class;
            },
        );
    }

    /**
     * Registers plugin utilities.
     *
     * @return void
     *
     * @author CraftPulse
     */
    private function _registerUtilities(): void
    {
        if ($this->getSettings()->retentionUtilities) {
            Event::on(Utilities::class, Utilities::EVENT_REGISTER_UTILITIES,
                function(RegisterComponentTypesEvent $event) {
                    $event->types[] = RetentionUtility::class;
                }
            );
        }

        // Audit Schema utility — Enterprise-only auditor surface that
        // renders `AuditLogService::ALLOWED_DETAILS_BY_EVENT` as a
        // read-only privacy contract. Edition gate at registration time
        // so Lite / Pro installs never see the utility class.
        //
        // Permission visibility: Craft's utilities index gates each
        // utility on the `utility:<utility-id>` permission. The plugin
        // additionally checks `pp:audit-view` here so an admin grant of
        // that permission alone is sufficient (without also having to
        // remember the utility-permission name); a user without
        // `pp:audit-view` doesn't see the utility registered at all.
        if ($this->getIsEnterprise()) {
            Event::on(Utilities::class, Utilities::EVENT_REGISTER_UTILITIES,
                function(RegisterComponentTypesEvent $event) {
                    $currentUser = Craft::$app->getUser()->getIdentity();
                    if ($currentUser === null) {
                        return;
                    }

                    if (!$currentUser->admin && !$currentUser->can('pp:audit-view')) {
                        return;
                    }

                    $event->types[] = AuditSchemaUtility::class;
                }
            );

            // Audit Export utility (G10) — same edition gate as
            // AuditSchemaUtility but a separate permission
            // (`pp:audit-export`). Export is a write-side privilege
            // (produces durable artifacts capable of leaving the host),
            // distinct from `pp:audit-view`'s read access — an auditor
            // grantee with the view permission alone shouldn't see the
            // utility because they can't usefully use it.
            Event::on(Utilities::class, Utilities::EVENT_REGISTER_UTILITIES,
                function(RegisterComponentTypesEvent $event) {
                    $currentUser = Craft::$app->getUser()->getIdentity();
                    if ($currentUser === null) {
                        return;
                    }

                    if (!$currentUser->admin && !$currentUser->can('pp:audit-export')) {
                        return;
                    }

                    $event->types[] = AuditExportUtility::class;
                }
            );

            // Compliance Dashboard utility (G3) — Enterprise-only
            // visible-exposure surface on top of the Phase G audit
            // infrastructure. Permission gate `pp:audit-view` (read
            // access) rather than `pp:audit-export` (write) — the
            // dashboard is read-only; the per-aggregate "Run report"
            // links go through `ReportController` which enforces the
            // same `pp:audit-view` permission on its actions.
            Event::on(Utilities::class, Utilities::EVENT_REGISTER_UTILITIES,
                function(RegisterComponentTypesEvent $event) {
                    $currentUser = Craft::$app->getUser()->getIdentity();
                    if ($currentUser === null) {
                        return;
                    }

                    if (!$currentUser->admin && !$currentUser->can('pp:audit-view')) {
                        return;
                    }

                    $event->types[] = ComplianceDashboardUtility::class;
                }
            );
        }
    }

    /**
     * Registers event listeners for password history caching and storage.
     *
     * Three-layer lifecycle:
     * 1. EVENT_BEFORE_SAVE — cache plaintext from newPassword
     * 2. EVENT_AFTER_SAVE — extract-and-clear cache, hash, store in history
     * 3. APPLICATION::EVENT_AFTER_REQUEST — safety net: clear all
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerPasswordHistoryListeners(): void
    {
        $settings = $this->getSettings();

        // Layer 1: Cache plaintext in EVENT_BEFORE_SAVE
        Event::on(
            User::class,
            User::EVENT_BEFORE_SAVE,
            function(ModelEvent $event) {
                /** @var User $user */
                $user = $event->sender;

                if (empty($user->newPassword)) {
                    return;
                }

                // Skip draft/revision elements
                if (ElementHelper::isDraftOrRevision($user)) {
                    return;
                }

                $cacheKey = ($user->id ?? 0) . ':' . spl_object_id($user);
                $this->getPasswordHistory()->cachePassword(
                    $user->id ?? 0,
                    $cacheKey,
                    $user->newPassword,
                );
            }
        );

        // Layer 2: Store hash in EVENT_AFTER_SAVE
        Event::on(
            User::class,
            User::EVENT_AFTER_SAVE,
            function(ModelEvent $event) use ($settings) {
                /** @var User $user */
                $user = $event->sender;

                // Skip draft/revision elements
                if (ElementHelper::isDraftOrRevision($user)) {
                    return;
                }

                // Recursion guard for forceChangeOnFirstLogin
                if (isset(self::$_processing[$user->id])) {
                    return;
                }

                $cacheKey = ($user->id) . ':' . spl_object_id($user);
                $plaintext = $this->getPasswordHistory()->getAndClearCache($cacheKey);

                // For new users, the BEFORE_SAVE cache key used "0:" since
                // the user had no ID yet. Try the fallback key.
                if ($plaintext === null && $event->isNew) {
                    $fallbackKey = '0:' . spl_object_id($user);
                    $plaintext = $this->getPasswordHistory()->getAndClearCache($fallbackKey);
                }

                // Resolve the audit context once. Pending-reason consume is
                // load-bearing for indirect change triggers (HIBP, force-
                // reset, expiry, first-login) — those triggers set
                // `passwordResetRequired = true` + a pending reason; THIS
                // save is the user actually completing that reset, so the
                // pending reason becomes the history row's `changeReason`.
                // No pending reason means a normal flow — fall back to
                // request-derived self-service (web) or CLI (console).
                $context = $plaintext !== null ? $this->_resolveAuditContext($user) : null;

                // Store password hash in history when feature is enabled
                // (count > 0). Universal across editions since 5.2.0.
                if ($context !== null && $settings->passwordHistoryCount > 0) {
                    try {
                        $hash = Craft::$app->getSecurity()->hashPassword($plaintext);
                        $this->getPasswordHistory()->savePasswordHash($user->id, $hash, $context);
                    } catch (Throwable $e) {
                        Craft::error(
                            'Failed to save password history: ' . $e->getMessage(),
                            'password-policy',
                        );
                    }
                }

                // Audit log + developer event: password changed
                if ($plaintext !== null) {
                    $this->getAuditLog()->logEvent(
                        userId: $user->id,
                        event: 'password_changed',
                        outcome: 'success',
                    );

                    // Fire developer event (Lite — free for ecosystem)
                    if ($this->hasEventHandlers(self::EVENT_PASSWORD_CHANGED)) {
                        $this->trigger(self::EVENT_PASSWORD_CHANGED, new PasswordChangedEvent([
                            'user' => $user,
                            'isNew' => $event->isNew,
                        ]));
                    }

                    // Consume the pending reason after a successful change.
                    // No-op when no row exists. Idempotent.
                    $this->getUserState()->clearPendingReason($user);
                }

                // Force change on first login for new users. The current
                // save persisted the operator-set initial password (admin
                // creating a user, registration form, etc.); flipping
                // `passwordResetRequired` here means the NEXT change is
                // the user's forced reset — so we set
                // `pendingResetReason = FirstLoginForced` so the next
                // history row records the right cause.
                if (
                    $event->isNew &&
                    $settings->forceChangeOnFirstLogin &&
                    !$user->passwordResetRequired
                ) {
                    self::$_processing[$user->id] = true;
                    try {
                        $user->passwordResetRequired = true;
                        Craft::$app->getElements()->saveElement($user, false);
                        $this->getUserState()->setPendingReason($user, ChangeReason::FirstLoginForced);
                    } catch (Throwable $e) {
                        Craft::error(
                            'Failed to set passwordResetRequired: ' . $e->getMessage(),
                            'password-policy',
                        );
                    } finally {
                        unset(self::$_processing[$user->id]);
                    }
                }
            }
        );
    }

    /**
     * Resolves the audit context for a password-change save inside the
     * central history-write listener. Three-tier precedence:
     *
     *  1. Explicit context via `UserStateService::setExplicitContext()` —
     *     D3's `ChangeUserPassword` admin action pins this so the row
     *     records `AdminChange` + `changedByUserId` regardless of any
     *     prior pending reason on the user.
     *  2. Pending-reset reason on the user_state row — HIBP-on-login,
     *     `ForcePasswordReset`, expiry, first-login propagate through
     *     this seam. Request IP/UA still attached so the history row
     *     records HOW the user completed the forced change.
     *  3. Default — `SelfService` (web) or `Cli` (console).
     *
     * Stays a private helper rather than a `UserStateService` method —
     * the listener is the only place that does the consume-and-fall-back
     * dance; pushing it into the service would obscure the seam.
     *
     * @param User $user
     * @return AuditContext
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveAuditContext(User $user): AuditContext
    {
        // Tier 1 — explicit context wins. The slot is consumed (single-use)
        // so a follow-up save in the same request can't pick up a stale
        // context. Admin direct change overrides any prior pending reason.
        $explicit = $this->getUserState()->consumeExplicitContext($user);

        if ($explicit !== null) {
            return $explicit;
        }

        // Tier 2 — pending-reset reason on user_state.
        $state = $this->getUserState()->getStateForUser($user);

        if ($state !== null && $state->pendingResetReason !== null) {
            $reason = ChangeReason::tryFrom($state->pendingResetReason);

            if ($reason !== null) {
                // Pending-reason path. Pull IP/UA off the active request so
                // the history row still records HOW the user completed the
                // forced change, even though WHY (the reason) was decided
                // when the trigger fired.
                return AuditContext::fromRequest(reason: $reason);
            }
        }

        // Tier 3 — no explicit context, no pending reason. Console maps to
        // `ChangeReason::Cli` so `users/set-password` and friends record
        // the right cause; web maps to `SelfService`.
        if (Craft::$app->getRequest()->getIsConsoleRequest()) {
            return AuditContext::cli();
        }

        return AuditContext::selfService();
    }

    /**
     * Registers the listener that fires
     * {@see self::EVENT_PASSWORD_VALIDATION} after Yii's `validate()`
     * runs on a User element. Hooks `User::EVENT_AFTER_VALIDATE` —
     * Yii's `Model::validate()` calls `afterValidate()` once per call,
     * which triggers this event after every rule (including the
     * plugin's password rules registered via `EVENT_DEFINE_RULES`)
     * has executed. At that point, password-attribute errors are
     * settled and listeners get a deterministic snapshot.
     *
     * Privacy invariant: never expose the plaintext password, derived
     * hash material, or any HIBP bucket payload through the event. The
     * event class accepts only the User element + an errors array +
     * the boolean validity flag — verified at the class level
     * ({@see PasswordValidationEvent}). Listeners that want to push
     * their own errors back onto the user can call
     * `$event->user->addError('newPassword', '…')` — Yii model errors
     * are mutable post-validate.
     *
     * Defensive guard: skip firing for User elements that have no
     * password attribute set (e.g. a name-only edit triggered an
     * unrelated validate() pass). Avoids noisy events for callers that
     * don't care about password validation.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerPasswordValidationEvent(): void
    {
        Event::on(
            User::class,
            User::EVENT_AFTER_VALIDATE,
            function(Event $event): void {
                /** @var User $user */
                $user = $event->sender;

                // Skip when neither password attribute is in scope —
                // the validate() call wasn't about passwords.
                if (
                    ($user->password ?? '') === '' &&
                    ($user->newPassword ?? '') === ''
                ) {
                    return;
                }

                if (!$this->hasEventHandlers(self::EVENT_PASSWORD_VALIDATION)) {
                    return;
                }

                // Aggregate password-specific errors from the User. Pull
                // both attributes — `password` (existing record) and
                // `newPassword` (mid-change) — so listeners see the
                // full picture regardless of save flow.
                $passwordErrors = array_merge(
                    $user->getErrors('password'),
                    $user->getErrors('newPassword'),
                );

                $this->trigger(
                    self::EVENT_PASSWORD_VALIDATION,
                    new PasswordValidationEvent([
                        'user' => $user,
                        'errors' => $passwordErrors,
                        'isValid' => empty($passwordErrors),
                    ]),
                );
            },
        );
    }

    /**
     * Registers listeners for Craft security events (Enterprise audit logging).
     *
     * Listens to the account lockout and unlock events
     * (`Users::EVENT_AFTER_LOCK_USER` / `EVENT_AFTER_UNLOCK_USER`) to
     * record them in the audit log. Gating happens inside
     * AuditLogService::logEvent().
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerCraftSecurityListeners(): void
    {
        // The Users service fires these events on itself, so
        // `$event->sender` is the service instance — the User element
        // lives on `UserEvent::$user`.
        Event::on(
            Users::class,
            Users::EVENT_AFTER_LOCK_USER,
            function(UserEvent $event) {
                $this->getAuditLog()->logEvent(
                    userId: $event->user->id,
                    event: 'account_locked',
                    outcome: 'warning',
                );
            }
        );

        Event::on(
            Users::class,
            Users::EVENT_AFTER_UNLOCK_USER,
            function(UserEvent $event) {
                $this->getAuditLog()->logEvent(
                    userId: $event->user->id,
                    event: 'account_unlocked',
                    outcome: 'success',
                );
            }
        );
    }

    /**
     * Registers a listener that observes user-group deletions and logs the
     * named policies whose junction rows are about to be dropped via FK
     * cascade. Hooks `EVENT_BEFORE_APPLY_GROUP_DELETE` so the junction rows
     * still exist when we query — `EVENT_AFTER_DELETE_USER_GROUP` would
     * fire after cascade and leave nothing to enumerate.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerUserGroupListeners(): void
    {
        Event::on(
            UserGroups::class,
            UserGroups::EVENT_BEFORE_APPLY_GROUP_DELETE,
            function(UserGroupEvent $event): void {
                try {
                    $group = $event->userGroup;
                    $policies = $this->getPolicies()->getPoliciesForGroupIds([$group->id]);

                    if (empty($policies)) {
                        return;
                    }

                    $names = implode(', ', array_map(fn($p) => $p->name, $policies));

                    $this->log(
                        'User group "{groupName}" (id: {groupId}) deleted; dropping policy assignments: {policies}',
                        [
                            'groupName' => $group->name,
                            'groupId' => $group->id,
                            'policies' => $names,
                        ],
                    );
                } catch (Throwable $e) {
                    Craft::warning(
                        'Failed to log policy assignments for deleted group: ' . $e->getMessage(),
                        'password-policy',
                    );
                }
            },
        );
    }

    /**
     * Registers a listener that propagates notification template rows to a
     * newly-added site. When `Sites::EVENT_AFTER_SAVE_SITE` fires with
     * `isNew = true`, copies every primary-site template row into the new
     * site so admins don't see a missing template on first edit.
     *
     * Defensive `try/catch (Throwable)` — if the propagation fails (e.g.
     * DB transient), log a warning. Site save itself is never blocked;
     * propagation is best-effort, and the runtime fallback in
     * `NotificationTemplateService::getTemplate()` covers the gap.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerSiteListeners(): void
    {
        Event::on(
            Sites::class,
            Sites::EVENT_AFTER_SAVE_SITE,
            function(SiteEvent $event): void {
                if (!$event->isNew) {
                    return;
                }

                try {
                    $this->getNotificationTemplates()->propagateToSite($event->site->id);
                } catch (Throwable $e) {
                    Craft::warning(
                        'Failed to propagate notification templates to new site: ' . $e->getMessage(),
                        'password-policy',
                    );
                }
            },
        );
    }

    /**
     * Registers plugin-managed system mailer messages so callers can
     * compose them via `Craft::$app->getMailer()->composeFromKey()`.
     *
     * Currently the only key registered here is `password-policy:audit-
     * export-ready` (G10) — the one-time-link email sent to the
     * requesting admin when an `AuditExportJob` finishes. The body is
     * an inline Twig string with token substitution; the System
     * Messages utility renders it editable for admins on Craft Pro+
     * licenses, but the default copy ships in this registration so a
     * fresh install works without any editorial step.
     *
     * Other plugin notification flows (`expiry-reminder`, `breach-
     * detected`) use the editable-templates surface
     * (`passwordpolicy_notification_templates`) instead, which gives
     * admins per-site override + activity logging at the cost of
     * additional DB plumbing. Phase G's audit export deliberately
     * uses the simpler `composeFromKey` path because the email isn't
     * something operators typically need to brand or translate at
     * the per-site level — defer to 5.3 if that changes.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerSystemMessages(): void
    {
        Event::on(
            SystemMessages::class,
            SystemMessages::EVENT_REGISTER_MESSAGES,
            static function(RegisterEmailMessagesEvent $event): void {
                $event->messages[] = [
                    'key' => 'password-policy:audit-export-ready',
                    'heading' => Craft::t(
                        'password-policy',
                        'When an audit-log export finishes',
                    ),
                    'subject' => Craft::t(
                        'password-policy',
                        'Your audit log export is ready',
                    ),
                    'body' => Craft::t(
                        'password-policy',
                        "Your audit log export is ready to download.\n\n"
                        . "**Download:** [{{ downloadUrl }}]({{ downloadUrl }})\n\n"
                        . "**Format:** {{ format }}\n"
                        . "**Rows:** {{ rowCount }}\n"
                        . "**Expires:** {{ expiresAt|datetime }}\n\n"
                        . 'The download link is one-time-use — clicking it serves the file '
                        . 'and immediately invalidates the link. Re-export from the CP utility '
                        . 'or `password-policy/audit/export --queue` console command if you '
                        . 'need another copy.',
                    ),
                ];
            },
        );
    }

    /**
     * Registers the HIBP-on-login Pro listener.
     *
     * Subscribes to `User::EVENT_BEFORE_AUTHENTICATE` (the only Craft 5
     * event that fires synchronously inside the login flow with the
     * plaintext password in scope). Hashes the plaintext to SHA-1, sends
     * only the 5-char k-anonymity prefix to the HIBP API, and on a match:
     *  1. Sets `$user->passwordResetRequired = true` (saved under the
     *     `$_processing` recursion guard so the password-history listener
     *     skips the re-save — the password isn't actually changing).
     *  2. Sends the `breach-detected` notification email (Pro pipeline).
     *  3. Writes an Enterprise audit-log entry (gated inside the listener
     *     because Lite/Pro installs don't have the audit log enabled).
     *  4. Fires `EVENT_BREACH_DETECTED` for consumer hooks.
     *
     * Privacy invariant: never log the plaintext, full SHA-1 hash, or full
     * prefix-and-suffix bucket. Only the 5-char prefix and a "match found"
     * boolean ever leave the listener.
     *
     * Defensive: HIBP API failures (timeout, 429, 5xx, TLS issue) are caught
     * and logged at WARNING level — login is never blocked.
     *
     * Dedup cache: 24h per user. Same user signing in repeatedly within a
     * day produces a single HIBP API call and a single notification.
     * The cache key intentionally omits the SHA-1 prefix — embedding it
     * alongside `userId` in an inspectable cache key (Redis/Memcache)
     * produces a `(userId, prefix)` ledger that recreates the linkability
     * property k-anonymity is designed to eliminate. One-call-per-user-per-
     * day is the effective dedup; per-prefix granularity isn't worth the
     * privacy trade-off.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerHibpOnLoginListener(): void
    {
        Event::on(
            User::class,
            User::EVENT_BEFORE_AUTHENTICATE,
            function(AuthenticateUserEvent $event): void {
                if (!$this->getSettings()->enableHibpOnLogin) {
                    return;
                }

                // Passkey-driven authentication leaves $event->password null —
                // nothing to check.
                $plaintext = $event->password;

                if ($plaintext === null || $plaintext === '') {
                    return;
                }

                /** @var User $user */
                $user = $event->sender;

                if (!$user->id) {
                    return;
                }

                try {
                    $this->_runHibpOnLoginCheck($user, $plaintext);
                } catch (Throwable $e) {
                    // Login must never break because of an HIBP path issue.
                    // Log opaque summary only — never include $plaintext or
                    // any derived hash material.
                    Craft::warning(
                        'HIBP-on-login check failed for user ' . $user->id . ': ' . $e->getMessage(),
                        'password-policy',
                    );
                }
            },
        );
    }

    /**
     * Performs the HIBP-on-login check against a plaintext password and runs
     * the breach-detected side effects when the password matches the breach
     * database.
     *
     * Intentionally separated from the listener registration so the
     * defensive try/catch in the listener can wrap one call site. The
     * `$plaintext` parameter is `#[\SensitiveParameter]` so PHP omits it
     * from stack traces if anything throws downstream.
     *
     * @param User $user the authenticating user
     * @param string $plaintext the plaintext password from the login form
     * @return void
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _runHibpOnLoginCheck(User $user, #[\SensitiveParameter] string $plaintext): void
    {
        // Site-wide HIBP rate-limit guard. If the API recently 429'd us,
        // skip the check entirely — login is never blocked, and we don't
        // want to hammer HIBP while already throttled. PasswordService::hibp()
        // also short-circuits on the same key, so this is defense-in-depth.
        if ($this->getPasswords()->isHibpBackoffActive()) {
            return;
        }

        $sha1Prefix = strtoupper(substr(sha1($plaintext), 0, 5));
        // Cache key uses userId only — see the dedup-cache note in the
        // listener registration docblock. The 5-char k-anonymity prefix
        // is computed here for the API call but intentionally NOT
        // embedded in the cache key; storing it alongside userId in
        // Redis/Memcache produces a privacy regression that the
        // k-anonymity model exists to prevent.
        $cacheKey = "pp:hibp-login:{$user->id}";

        // 24h dedup window. Yii's cache `get()` returns `false` for missing
        // keys, so we encode the cached state as a string ("breached" /
        // "clean") to disambiguate "no cache" from a cached clean result.
        $cached = Craft::$app->getCache()->get($cacheKey);

        if ($cached !== false) {
            // Cached run — no second API call, no second notification.
            return;
        }

        // hibp() does the prefix lookup + suffix scan and never logs the
        // plaintext (verified in PasswordService::hibp() — only the prefix
        // appears on the wire and in API logs).
        $result = $this->getPasswords()->hibp($plaintext);

        if ($result === null) {
            // API failure — don't cache (we want next login to retry),
            // don't notify, don't block, don't update state. PasswordService
            // already logged the exception at WARNING level.
            return;
        }

        // Cache the outcome for 24h. String values to avoid the false/missing
        // ambiguity in Yii's cache contract. Daily-active users with the same
        // password generate one HIBP call and (at most) one notification per
        // day until they change their password.
        Craft::$app->getCache()->set($cacheKey, $result === true ? 'breached' : 'clean', 86400);

        // Record the check on every non-API-failure outcome — `lastBreachCheckAt`
        // updates regardless, `lastBreachDetectedAt` only when detected.
        // The 24h cache short-circuits at the top means we record once per
        // user-prefix per day, which is the correct cadence.
        $this->getUserState()->recordBreachCheck($user, $result === true);

        if ($result !== true) {
            return;
        }

        // Breach detected — run side effects.
        $detectedAt = new \DateTime('now');

        // 1. Force a password reset on next login. We set
        //    `passwordResetRequired = true` and re-save WITHOUT changing
        //    the password.
        //
        //    Why this is safe (the real reason): `ProjectConfig::muteEvents`
        //    only gates project-config change events — it does NOT suppress
        //    element-save events, so it would do nothing here. The actual
        //    guard against the EVENT_AFTER_SAVE password-history listener
        //    re-entering on this flag-only save is the `$_processing`
        //    set, mirrored from the forceChangeOnFirstLogin re-save: the
        //    listener checks `isset(self::$_processing[$user->id])` at the
        //    top and returns early. Because `newPassword` is unset on this
        //    save the listener wouldn't write a history row anyway (its
        //    plaintext cache lookup misses), but the guard makes the intent
        //    explicit and matches the sibling flow.
        //
        //    Also pin a pending `BreachForced` reason on the user_state row
        //    so the user's NEXT password change records the right
        //    `changeReason` in history.
        self::$_processing[$user->id] = true;
        try {
            $user->passwordResetRequired = true;
            Craft::$app->getElements()->saveElement($user, false);
            $this->getUserState()->setPendingReason($user, ChangeReason::BreachForced);
        } catch (Throwable $e) {
            Craft::warning(
                'Failed to set passwordResetRequired on breached user ' . $user->id . ': ' . $e->getMessage(),
                'password-policy',
            );
        } finally {
            unset(self::$_processing[$user->id]);
        }

        // 2. Send the breach-detected notification.
        try {
            $this->getNotification()->sendBreachDetected($user, $detectedAt);
        } catch (Throwable $e) {
            Craft::warning(
                'Failed to send breach-detected email for user ' . $user->id . ': ' . $e->getMessage(),
                'password-policy',
            );
        }

        // 2b. Feature 3 — route a COPY of the breach alert to each
        //     group-designated security contact resolved from the user's
        //     group set. Pro-gated + throttled per group inside the helper;
        //     the HIBP-on-login listener already only registers on Pro, but
        //     the helper's own `getIsPro()` guard is the defense-in-depth.
        //     Wrapped so a routing failure can't unwind the breach side
        //     effects below (passwordResetRequired, audit row, event).
        try {
            $this->_dispatchGroupAlerts($user, 'breach_detected');
        } catch (Throwable $e) {
            Craft::warning(
                'Per-group breach alert routing failed for user ' . $user->id . ': ' . $e->getMessage(),
                'password-policy',
            );
        }

        // 3. Audit-log entry. Capture is universal (G1) — the service's
        //    own `enableAuditLog` feature-flag check is the only gate;
        //    edition gates apply to read surfaces (verifier CLI, dashboard,
        //    forwarder), not to writes.
        $this->getAuditLog()->logEvent(
            userId: $user->id,
            event: 'breach_detected',
            outcome: 'warning',
        );

        // 4. Fire the public event.
        if ($this->hasEventHandlers(self::EVENT_BREACH_DETECTED)) {
            $this->trigger(self::EVENT_BREACH_DETECTED, new BreachDetectedEvent([
                'user' => $user,
                'sha1Prefix' => $sha1Prefix,
                'detectedAt' => $detectedAt,
            ]));
        }

        // Privacy: log only that a match was found and the user notified.
        // Never include $plaintext or any derived material.
        $this->log(
            'HIBP-on-login match: user {userId} notified, passwordResetRequired set',
            ['userId' => $user->id],
        );
    }

    /**
     * Registers the Feature 1 new-device listener.
     *
     * Subscribes to `yii\web\User::EVENT_AFTER_LOGIN` — fired post-auth
     * with the request user-agent + IP in scope. This is deliberately NOT
     * `User::EVENT_BEFORE_AUTHENTICATE` (the HIBP hook): AFTER_LOGIN also
     * covers passkey + remember-me logins, which BEFORE_AUTHENTICATE
     * misses.
     *
     * The listener registers on EVERY edition. On each login it resolves
     * the UA + IP from the request (skipping cleanly when there is no web
     * request, e.g. console / impersonation paths with no request scope)
     * and calls `DeviceTrackingService::recordLogin()`, which writes the
     * `passwordpolicy_known_devices` row on every edition (capture is
     * universal per `project_audit_capture_principle.md`).
     *
     * When the device is NEW (no prior row for the fingerprint):
     *  1. The `NewDeviceDetectedEvent` fires on every edition — a free
     *     ecosystem hook.
     *  2. On Enterprise + `enableAuditLog`, a `new_device` audit row is
     *     written (geo-excluded from the hash chain, raw UA/IP never in
     *     the details allowlist).
     *  3. On Enterprise + `enableNewDeviceAlerts`, the new-device alert
     *     email is sent — gated through `AlertCooldownService` (one alert
     *     per user per `DEFAULT_COOLDOWN_NEW_DEVICE` window) and enriched
     *     with a geo hint when `GeoIpService` resolves the IP.
     *
     * Privacy: the raw UA + IP stay in request scope. Only the derived
     * fingerprint (never logged), the masked IP, and the human-readable
     * label are persisted or surfaced. A device-tracking failure must
     * never break the login, so the body is wrapped in a defensive
     * try/catch.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerNewDeviceListener(): void
    {
        Event::on(
            WebUser::class,
            WebUser::EVENT_AFTER_LOGIN,
            function(WebUserEvent $event): void {
                /** @var User $user */
                $user = $event->identity;

                if (!$user->id) {
                    return;
                }

                $request = Craft::$app->getRequest();

                if ($request->getIsConsoleRequest()) {
                    return;
                }

                $userAgent = $request->getUserAgent();
                $rawIp = $request->getUserIP();

                if ($userAgent === null || $rawIp === null) {
                    return;
                }

                try {
                    $this->_recordLoginDevice($user, $userAgent, $rawIp);
                } catch (Throwable $e) {
                    // Login must never break because of a device-tracking
                    // issue. Log an opaque summary only — never the raw
                    // UA / IP / fingerprint.
                    Craft::warning(
                        'New-device tracking failed for user ' . $user->id . ': ' . $e->getMessage(),
                        'password-policy',
                    );
                }
            },
        );
    }

    /**
     * Records a login for device-tracking and runs the new-device side
     * effects when the device is new.
     *
     * Separated from the listener so the defensive try/catch wraps one
     * call site. The capture (`recordLogin`) runs on every edition; the
     * audit row + alert email are Enterprise-gated, the cooldown throttles
     * the email, and the `NewDeviceDetectedEvent` fires on every edition.
     *
     * @param User $user the authenticated user
     * @param string $userAgent the raw request user-agent
     * @param string $rawIp the raw request IP
     * @return void
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordLoginDevice(User $user, string $userAgent, string $rawIp): void
    {
        $siteId = Craft::$app->getRequest()->getIsCpRequest()
            ? null
            : (Craft::$app->getSites()->getCurrentSite()->id ?? null);

        $isNew = $this->getDeviceTracking()->recordLogin($user, $userAgent, $rawIp, $siteId);

        if (!$isNew) {
            return;
        }

        $label = $this->getDeviceLabel()->label($userAgent);
        $maskedIp = $this->getDeviceLabel()->maskIp($rawIp);

        // Enterprise audit row — gated here because Lite/Pro installs
        // don't expose the audit log. The details allowlist (`source`,
        // `deviceLabel`) carries the masked label only — never the raw
        // UA/IP, which `logEvent()` would strip anyway.
        if ($this->getIsEnterprise() && $this->getSettings()->enableAuditLog) {
            $this->getAuditLog()->logEvent(
                userId: (int)$user->id,
                event: 'new_device',
                details: [
                    'source' => 'login',
                    'deviceLabel' => $label,
                ],
            );
        }

        // Enterprise new-device alert email — cooldown-throttled to one
        // alert per user per window. The geo-enriched label is built only
        // when we are actually going to send (after the cooldown clears).
        if ($this->getIsEnterprise() && $this->getSettings()->enableNewDeviceAlerts) {
            $cleared = $this->getAlertCooldown()->shouldFire(
                'new_device',
                "user:{$user->id}",
                AlertCooldownService::DEFAULT_COOLDOWN_NEW_DEVICE,
            );

            if ($cleared) {
                $this->getNotification()->sendNewDeviceAlert(
                    $user,
                    $this->_enrichLabelWithGeo($label, $rawIp),
                    $maskedIp,
                );
            }
        }

        // Feature 3 — route a COPY of the new-device alert to each
        // group-designated security contact resolved from the user's group
        // set. Pro-gated (NOT Enterprise) and independent of
        // `enableNewDeviceAlerts`: a Pro operator who wired group alerts
        // wants the contact notified of new-device events for their group's
        // members even on a Pro install that doesn't expose the end-user
        // new-device email. Throttled per group + event inside the helper.
        $this->_dispatchGroupAlerts($user, 'new_device');

        // Public ecosystem hook — fires on every edition after capture.
        if ($this->hasEventHandlers(self::EVENT_NEW_DEVICE_DETECTED)) {
            $this->trigger(self::EVENT_NEW_DEVICE_DETECTED, new NewDeviceDetectedEvent([
                'user' => $user,
                'deviceLabel' => $label,
                'maskedIp' => $maskedIp,
                'siteId' => $siteId,
            ]));
        }
    }

    /**
     * Appends a geo hint to a device label when `GeoIpService` resolves
     * the IP, e.g. "Chrome on macOS — US". Returns the bare label
     * unchanged when geolocation is disabled or the IP is unresolvable.
     *
     * Gated by `geoIpEnabled` inside `GeoIpService::lookup()`; the raw IP
     * is used for the lookup only and never persisted.
     *
     * @param string $label the base device label
     * @param string $rawIp the raw request IP
     * @return string
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _enrichLabelWithGeo(string $label, string $rawIp): string
    {
        $geo = $this->getGeoIp()->lookup($rawIp);

        if ($geo === null) {
            return $label;
        }

        $location = $geo->region !== null && $geo->countryCode !== null
            ? "{$geo->region}, {$geo->countryCode}"
            : ($geo->countryCode ?? $geo->region);

        if ($location === null) {
            return $label;
        }

        return "{$label} — {$location}";
    }

    /**
     * Feature 3 — routes a COPY of a user-facing alert to each
     * group-designated security contact resolved from the affected user's
     * group set.
     *
     * Shared by both alert seams (the HIBP-on-login `breach_detected` path
     * and the new-device `new_device` path). Pro-gated: Lite installs never
     * route group copies. Resolution heeds the per-group hazard — recipients
     * come from `GroupAlertService::recipientsForUser()`, which reads the
     * user's RESOLVED group membership, NOT a global setting
     * (`project_per_group_resolution_hazard.md`).
     *
     * Each recipient is throttled independently via
     * `AlertCooldownService::shouldFire("group:{groupId}:{eventType}", …)` so
     * a burst (mass HIBP detection against one group's members) routes a
     * single copy to the contact per window rather than one per affected
     * user. A send / cooldown failure for one recipient must never break the
     * login or the originating alert, so each iteration is wrapped
     * defensively.
     *
     * Minimal PII: the contact receives the event type and a single user
     * identifier (username falling back to email) — the same convention the
     * admin-security-alert surface uses, never more than the user's own
     * alert would expose.
     *
     * @param User $user the user who triggered the originating alert
     * @param string $eventType `breach_detected` or `new_device`
     * @return void
     *
     * @throws InvalidConfigException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dispatchGroupAlerts(User $user, string $eventType): void
    {
        if (!$this->getIsPro()) {
            return;
        }

        $recipients = $this->getGroupAlerts()->recipientsForUser($user, $eventType);

        if ($recipients === []) {
            return;
        }

        $userIdentifier = $user->username ?? $user->email ?? (string)$user->id;

        foreach ($recipients as $recipientEmail => $groupId) {
            try {
                $cleared = $this->getAlertCooldown()->shouldFire(
                    'group_alert:' . $eventType,
                    "group:{$groupId}:{$eventType}",
                    AlertCooldownService::DEFAULT_COOLDOWN_GROUP_ALERT,
                );

                if (!$cleared) {
                    continue;
                }

                $this->getNotification()->sendGroupAlert($recipientEmail, $eventType, $userIdentifier);

                if ($this->hasEventHandlers(self::EVENT_GROUP_ALERT_DISPATCHED)) {
                    $this->trigger(self::EVENT_GROUP_ALERT_DISPATCHED, new GroupAlertDispatchedEvent([
                        'user' => $user,
                        'groupId' => $groupId,
                        'eventType' => $eventType,
                        'recipientEmail' => $recipientEmail,
                    ]));
                }
            } catch (Throwable $e) {
                // A single contact's send failure must not break the login,
                // the originating alert, or the other recipients. Log an
                // opaque summary — never the user identifier or recipient.
                Craft::warning(
                    'Per-group alert routing failed for a contact on event ' . $eventType
                        . ' (user ' . $user->id . '): ' . $e->getMessage(),
                    'password-policy',
                );
            }
        }
    }

    /**
     * Registers the request-end cleanup for plaintext password cache.
     *
     * This is the safety net: even if all other cleanup fails, no plaintext
     * survives past the end of the HTTP request or queue job.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerRequestCleanup(): void
    {
        Event::on(
            Application::class,
            Application::EVENT_AFTER_REQUEST,
            function() {
                $this->getPasswordHistory()->clearAllCache();
                $this->getUserState()->clearExplicitContexts();
            }
        );
    }

    /**
     * Registers Craft GC hook as a best-effort fallback for data retention.
     *
     * Craft's GC runs probabilistically (1 in 100,000 requests by default).
     * On low-traffic sites this may fire infrequently. For guaranteed retention
     * compliance, schedule `password-policy/gc/run` via cron.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerGarbageCollection(): void
    {
        Event::on(
            Gc::class,
            Gc::EVENT_RUN,
            fn() => $this->runGc(),
        );
    }

    /**
     * Registers User index integration: condition rules, table
     * attributes (D2), sort options (D2), and the force-reset bulk
     * action.
     *
     * The table-attribute side relies on the per-request preload in
     * {@see UserIndexService::preloadForUsers()} to keep cell rendering
     * out of N+1 territory. The preload runs once per request behind a
     * static flag — re-firing across many `EVENT_DEFINE_ATTRIBUTE_HTML`
     * callbacks for the same render cycle is a no-op.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerUserIndexIntegration(): void
    {
        // Condition rules for user filtering. The pre-D2 trio
        // (Expired, ResetRequired, NeverChanged) covers the boolean
        // axes; D2.3 adds parameterised + multi-select + drift rules
        // alongside them. PolicyDriftConditionRule is gated on Pro +
        // Craft Team-or-better at registration so a Lite or Solo
        // install doesn't expose a rule that always returns zero
        // matches. PasswordExpiredConditionRule and
        // PasswordExpiringWithinConditionRule deliberately overlap —
        // operators want the lightswitch ergonomic for "expired
        // yes/no" plus the parameterised rule for "expiring within N
        // days." Both are kept.
        Event::on(
            UserCondition::class,
            UserCondition::EVENT_REGISTER_CONDITION_RULES,
            function(RegisterConditionRulesEvent $event) {
                $event->conditionRules[] = PasswordExpiredConditionRule::class;
                $event->conditionRules[] = PasswordResetRequiredConditionRule::class;
                $event->conditionRules[] = PasswordNeverChangedConditionRule::class;
                $event->conditionRules[] = PasswordExpiringWithinConditionRule::class;
                $event->conditionRules[] = LastChangeReasonConditionRule::class;
                $event->conditionRules[] = PasswordStatusConditionRule::class;

                if ($this->getIsPro()) {
                    $event->conditionRules[] = BreachedRecentlyConditionRule::class;

                    if ($this->isCraftTeamOrBetter()) {
                        $event->conditionRules[] = PolicyDriftConditionRule::class;
                    }
                }
            },
        );

        // Bulk element actions on the Users index. Bulk-friendly only:
        //
        // `ForcePasswordReset` (Pro) — flips `passwordResetRequired`
        // and pins an `AdminForceReset` pending reason. Idempotent at
        // the user level; safe to apply across many rows.
        //
        // `SendPasswordResetEmail` (all editions) — pins a pending
        // `AdminForceReset` reason on user_state and sends Craft's
        // standard reset email. One email per row, no shared state
        // between targets.
        //
        // `ChangeUserPassword` is intentionally absent: applying the
        // same password to N users is a security anti-pattern (one
        // leak compromises all). It lives only on the per-user edit
        // screen action menu (see {@see self::_registerUserEditActionMenu()}).
        //
        // Both registered actions respect `allowAdminChanges = false`
        // via their own `getTriggerHtml()` short-circuits.
        Event::on(
            User::class,
            User::EVENT_REGISTER_ACTIONS,
            function(RegisterElementActionsEvent $event) {
                if ($this->getIsPro()) {
                    $event->actions[] = ForcePasswordReset::class;
                }

                $event->actions[] = SendPasswordResetEmail::class;
            },
        );

        // Column registration on the Users element index. Edition gates
        // live in `UserIndexService::getAttributesForRegistration()` so
        // both this listener and any direct callers see a consistent
        // shape.
        Event::on(
            User::class,
            Element::EVENT_REGISTER_TABLE_ATTRIBUTES,
            function(RegisterElementTableAttributesEvent $event): void {
                $event->tableAttributes = array_merge(
                    $event->tableAttributes,
                    $this->getUserIndex()->getAttributesForRegistration(),
                );
            },
        );

        // Per-cell HTML rendering. The handler defers to
        // `renderAttributeHtml()`, which short-circuits to null for
        // non-plugin attributes — leaves Craft's own cell rendering
        // untouched. The service caches per-user state once preloaded;
        // additional cells for the same user are array lookups.
        Event::on(
            User::class,
            Element::EVENT_DEFINE_ATTRIBUTE_HTML,
            function(DefineAttributeHtmlEvent $event): void {
                /** @var User $user */
                $user = $event->sender;
                $service = $this->getUserIndex();

                // Lazy-load: the first cell encountering this user
                // primes the cache; later cells for the same user are
                // free. Test surfaces drive a deliberate `preloadForUsers()`
                // up-front to assert the bounded query count contract.
                if ($user->id !== null) {
                    $service->preloadForUsers([$user->id]);
                }

                $html = $service->renderAttributeHtml($user, $event->attribute);

                if ($html !== null) {
                    $event->html = $html;
                }
            },
        );

        // Sort options. Cheap-to-sort columns only — see
        // `UserIndexService::getSortOptions()` for the rationale.
        Event::on(
            User::class,
            Element::EVENT_REGISTER_SORT_OPTIONS,
            function(RegisterElementSortOptionsEvent $event): void {
                $service = $this->getUserIndex();
                $sortMappings = [];

                foreach (array_keys($service->getSortOptions()) as $attribute) {
                    $mapping = $service->getSortMapping($attribute);

                    if ($mapping === null) {
                        continue;
                    }

                    $sortMappings[] = [
                        'label' => $service->getSortOptions()[$attribute],
                        'orderBy' => array_keys($mapping)[0],
                        'attribute' => $attribute,
                    ];
                }

                if (empty($sortMappings)) {
                    return;
                }

                $event->sortOptions = array_merge($event->sortOptions, $sortMappings);
            },
        );
    }

    /**
     * Registers the "Password Security" left-nav screen on the User
     * edit experience, gated on the same `pp:force-reset-passwords` /
     * `pp:change-user-passwords` permission predicate the
     * {@see UserSecurityController::beforeAction()} enforces.
     *
     * Wired through `UsersController::EVENT_DEFINE_EDIT_SCREENS`
     * (since Craft 5.0) — fired from `EditUserTrait::asEditUserScreen()`
     * between the native screens (Profile, Permissions, Preferences,
     * Addresses) and the auth screens (Password & Verification,
     * Passkeys). The plugin-defined screen renders as a real left-nav
     * item alongside Profile/Permissions/Addresses with no template
     * hacks and no separate "go to standalone page" indirection.
     *
     * The standalone controller, URL rule, and template all stay
     * unchanged from the prior sidebar-pointer iteration. Only the
     * registration point changed.
     *
     * Read-only mode (`allowAdminChanges = false`) does NOT suppress
     * the screen — the linked page renders read-only data (status +
     * resolved policy) which is fine to view; the page template
     * disables form controls via `readOnlyNotice()` + the `disabled`
     * attribute on the force-reset button.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerUserEditScreen(): void
    {
        Event::on(
            UsersController::class,
            UsersController::EVENT_DEFINE_EDIT_SCREENS,
            static function(DefineEditUserScreensEvent $event): void {
                if (!UserSecurityController::callerHasViewPermission()) {
                    return;
                }

                $userId = $event->editedUser->id;

                if ($userId === null) {
                    return;
                }

                $event->screens['password-security'] = [
                    'label' => Craft::t('password-policy', 'Password Security'),
                    'url' => UrlHelper::cpUrl("password-policy/users/{$userId}/security"),
                ];
            },
        );
    }

    /**
     * Registers the per-user action-menu items shown in the "…"
     * disclosure menu next to the Save button on the User edit screen.
     * Hooks `Element::EVENT_DEFINE_ACTION_MENU_ITEMS` (since Craft 5.0)
     * — a separate surface from the index bulk-action menu wired
     * through `User::EVENT_REGISTER_ACTIONS`.
     *
     * Items registered:
     *
     *  - **Force password reset** (Pro, gated on `pp:force-reset-passwords`)
     *    — POST to `password-policy/user-security/force-reset` with
     *    the target userId. Idempotent flip; admin users are silently
     *    skipped server-side. Moved out of `RetentionController` in
     *    5.2.0 (pre-tag fix-pack) so the admin-on-user surface owns
     *    the write that drives it.
     *  - **Send password reset email** (gated on `pp:change-user-passwords`)
     *    — POST to `password-policy/user-password/send-reset-email`,
     *    elevated session required (the controller's `beforeAction()`
     *    enforces this; declaring it on the menu item lets Craft
     *    pre-prompt for re-auth before firing the action).
     *  - **Change password…** (gated on `pp:change-user-passwords`) —
     *    JS-driven Garnish modal (the same modal the index trigger
     *    used to surface; see {@see ChangeUserPassword::registerModalHelper()}).
     *    Single-user only — bulk same-password changes are a security
     *    anti-pattern.
     *
     * Read-only mode (`allowAdminChanges = false`) suppresses every
     * item — admins can still navigate to the Password Security screen
     * to view status, but can't write. Self-targeting also short-
     * circuits — admins set their own password via the standard My
     * Account screen, not this admin-on-user surface.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerUserEditActionMenu(): void
    {
        Event::on(
            User::class,
            Element::EVENT_DEFINE_ACTION_MENU_ITEMS,
            function(DefineMenuItemsEvent $event): void {
                /** @var User $user */
                $user = $event->sender;

                if ($user->id === null) {
                    return;
                }

                if (!Craft::$app->getConfig()->getGeneral()->allowAdminChanges) {
                    return;
                }

                $currentUser = Craft::$app->getUser()->getIdentity();

                if ($currentUser === null || $currentUser->id === $user->id) {
                    return;
                }

                $userId = $user->id;
                $editScreenUrl = UrlHelper::cpUrl("users/{$userId}");

                if ($this->getIsPro() && $currentUser->can('pp:force-reset-passwords')) {
                    $event->items[] = [
                        'icon' => 'asterisk',
                        'label' => Craft::t('password-policy', 'Force password reset'),
                        'action' => 'password-policy/user-security/force-reset',
                        'params' => ['userId' => $userId],
                        'redirect' => $editScreenUrl,
                        'confirm' => Craft::t(
                            'password-policy',
                            'Are you sure you want to force a password reset on this user’s next login?',
                        ),
                    ];
                }

                if ($currentUser->can('pp:change-user-passwords')) {
                    $event->items[] = [
                        'icon' => 'paper-plane',
                        'label' => Craft::t('password-policy', 'Send password reset email'),
                        'action' => 'password-policy/user-password/send-reset-email',
                        'params' => ['userId' => $userId],
                        'redirect' => $editScreenUrl,
                        'requireElevatedSession' => true,
                    ];

                    $changeId = sprintf('pp-change-password-%s', mt_rand());
                    $event->items[] = [
                        'id' => $changeId,
                        'icon' => 'key',
                        'label' => Craft::t('password-policy', 'Change password…'),
                    ];

                    $view = Craft::$app->getView();
                    ChangeUserPassword::registerModalHelper($view);

                    $labels = ChangeUserPassword::modalLabels();
                    $idJs = Json::encode($changeId);
                    $userIdJs = Json::encode($userId);

                    $view->registerJs(<<<JS
(() => {
    const btn = document.getElementById({$idJs});
    if (!btn) {
        return;
    }
    \$(btn).on('activate', () => {
        Craft.PasswordPolicy.openChangePasswordModal({
            userId: {$userIdJs},
            actionUrl: {$labels['actionUrl']},
            modalTitle: {$labels['modalTitle']},
            newLabel: {$labels['newLabel']},
            confirmLabel: {$labels['confirmLabel']},
            submitLabel: {$labels['submitLabel']},
            cancelLabel: {$labels['cancelLabel']},
            showLabel: {$labels['showLabel']},
            hideLabel: {$labels['hideLabel']},
            genericError: {$labels['genericError']},
        });
    });
})();
JS);
                }
            },
        );
    }

    /**
     * Registers a custom log target.
     *
     * @return void
     *
     * @see LineFormatter::SIMPLE_FORMAT
     *
     * @author CraftPulse
     */
    private function _registerLogTarget(): void
    {
        if (Craft::getLogger()->dispatcher instanceof Dispatcher) {
            Craft::getLogger()->dispatcher->targets[] = new MonologTarget([
                'name' => 'password-policy',
                'categories' => ['password-policy'],
                'level' => LogLevel::INFO,
                'logContext' => false,
                'allowLineBreaks' => true,
                'formatter' => new LineFormatter(
                    format: "%datetime% [%channel%.%level_name%] %message% %context%\n",
                    dateFormat: 'Y-m-d H:i:s',
                ),
            ]);
        }
    }
}
