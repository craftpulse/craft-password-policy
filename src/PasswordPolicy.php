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
use craft\base\Model;
use craft\base\Plugin;
use craft\elements\conditions\users\UserCondition;
use craft\elements\User;
use craft\events\AuthenticateUserEvent;
use craft\events\DefineRulesEvent;
use craft\events\ModelEvent;
use craft\events\RegisterComponentTypesEvent;
use craft\events\RegisterConditionRulesEvent;
use craft\events\RegisterElementActionsEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\events\RegisterUserPermissionsEvent;
use craft\events\SiteEvent;
use craft\events\TemplateEvent;
use craft\events\UserGroupEvent;
use craft\helpers\ArrayHelper;
use craft\helpers\ElementHelper;
use craft\helpers\Json;
use craft\log\MonologTarget;
use craft\services\Gc;
use craft\services\Sites;
use craft\services\UserGroups;
use craft\services\UserPermissions;
use craft\services\Users;
use craft\services\Utilities;
use craft\web\Application;
use craft\web\twig\variables\CraftVariable;
use craft\web\UrlManager;
use craft\web\View;
use craftpulse\passwordpolicy\assetbundles\passwordpolicy\PasswordPolicyAsset;
use craftpulse\passwordpolicy\elements\actions\ForcePasswordReset;
use craftpulse\passwordpolicy\elements\conditions\PasswordExpiredConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordNeverChangedConditionRule;
use craftpulse\passwordpolicy\elements\conditions\PasswordResetRequiredConditionRule;
use craftpulse\passwordpolicy\events\BreachDetectedEvent;
use craftpulse\passwordpolicy\events\PasswordChangedEvent;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\rules\UserRules;
use craftpulse\passwordpolicy\services\ServicesTrait;
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
    public string $schemaVersion = '2.3.0';

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

        $encoded_params = str_replace('\\', '', Json::encode($params));

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

        if ($this->getIsPro() && $settings->passwordHistoryCount > 0) {
            $results['passwordHistory'] = $this->getPasswordHistory()->purgeExpiredHistory(
                $settings->passwordHistoryExpiryDays,
                $settings->passwordHistoryCount,
            );
        }

        if ($this->getIsPro()) {
            $results['notificationLog'] = $this->getNotification()->pruneOldEntries(
                $settings->notificationLogRetentionDays,
            );
        }

        if ($this->getIsEnterprise() && $settings->enableAuditLog) {
            $results['auditLog'] = $this->getAuditLog()->purgeOldEntries(
                $settings->auditLogRetentionDays,
            );
        }

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
        if ($this->getIsPro() && $currentUser->can('pp:notification-templates-manage')) {
            $subNavs['notifications'] = [
                'label' => Craft::t('password-policy', 'Notifications'),
                'url' => 'password-policy/notifications',
            ];
        }

        // Settings visible in read-only mode too (admins can view active policy)
        if ($currentUser->can('pp:settings')) {
            $subNavs['settings'] = [
                'label' => 'Settings',
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

        // Safety net: clear any remaining cached passwords at end of request
        $this->_registerRequestCleanup();

        $this->_registerUserPermissions();
        $this->_registerUtilities();
        $this->_registerUserIndexIntegration();
        $this->_registerGarbageCollection();
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
                        'password-policy/notifications/<key:[\w\-]+>' => 'password-policy/notification-template/edit',
                        'password-policy/notifications/<key:[\w\-]+>/save' => 'password-policy/notification-template/save',
                        'password-policy/notifications/<key:[\w\-]+>/test-send' => 'password-policy/notification-template/test-send',
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
                $event->permissions[] = [
                    'heading' => 'Password Policy',
                    'permissions' => [
                        'pp:settings' => [
                            'label' => Craft::t('password-policy', 'Manage plugin settings.'),
                        ],
                        'pp:force-reset-passwords' => [
                            'label' => Craft::t('password-policy', 'Force reset passwords retention access.'),
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
                    ],
                ];
            }
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

                // Store password hash in history if Pro and history enabled
                if ($plaintext !== null && $this->getIsPro() && $settings->passwordHistoryCount > 0) {
                    try {
                        $hash = Craft::$app->getSecurity()->hashPassword($plaintext);
                        $this->getPasswordHistory()->savePasswordHash($user->id, $hash);
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
                }

                // Force change on first login for new users
                if (
                    $event->isNew &&
                    $settings->forceChangeOnFirstLogin &&
                    !$user->passwordResetRequired
                ) {
                    self::$_processing[$user->id] = true;
                    try {
                        $user->passwordResetRequired = true;
                        Craft::$app->getElements()->saveElement($user, false);
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
     * Registers listeners for Craft security events (Enterprise audit logging).
     *
     * Listens to lockout, unlock, and login failure events to record them
     * in the audit log. Gating happens inside AuditLogService::logEvent().
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerCraftSecurityListeners(): void
    {
        // Account locked
        Event::on(
            Users::class,
            Users::EVENT_AFTER_LOCK_USER,
            function(Event $event) {
                /** @var User $user */
                $user = $event->sender;
                $this->getAuditLog()->logEvent(
                    userId: $user->id,
                    event: 'account_locked',
                    outcome: 'warning',
                );
            }
        );

        // Account unlocked
        Event::on(
            Users::class,
            Users::EVENT_AFTER_UNLOCK_USER,
            function(Event $event) {
                /** @var User $user */
                $user = $event->sender;
                $this->getAuditLog()->logEvent(
                    userId: $user->id,
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
     * Registers the HIBP-on-login Pro listener.
     *
     * Subscribes to `User::EVENT_BEFORE_AUTHENTICATE` (the only Craft 5
     * event that fires synchronously inside the login flow with the
     * plaintext password in scope). Hashes the plaintext to SHA-1, sends
     * only the 5-char k-anonymity prefix to the HIBP API, and on a match:
     *  1. Sets `$user->passwordResetRequired = true` (saved with `muteEvents`
     *     so the password-history listeners don't fire spuriously).
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
     * Dedup cache: 24h on `(userId, sha1Prefix)`. Same user + same password
     * within a day produces a single notification; lets daily-active users
     * sign in repeatedly without spamming HIBP or themselves.
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
        $cacheKey = "pp:hibp-login:{$user->id}:{$sha1Prefix}";

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
            // don't notify, don't block. PasswordService already logged the
            // exception at ERROR level.
            return;
        }

        // Cache the outcome for 24h. String values to avoid the false/missing
        // ambiguity in Yii's cache contract. Daily-active users with the same
        // password generate one HIBP call and (at most) one notification per
        // day until they change their password.
        Craft::$app->getCache()->set($cacheKey, $result === true ? 'breached' : 'clean', 86400);

        if ($result !== true) {
            return;
        }

        // Breach detected — run side effects.
        $detectedAt = new \DateTime('now');

        // 1. Force a password reset on next login. Save with muteEvents to
        //    keep the password-history listeners from firing spurious
        //    PasswordChangedEvent — the password isn't actually changing.
        $projectConfig = Craft::$app->getProjectConfig();
        $previousMute = $projectConfig->muteEvents;
        $projectConfig->muteEvents = true;
        try {
            $user->passwordResetRequired = true;
            Craft::$app->getElements()->saveElement($user, false);
        } catch (Throwable $e) {
            Craft::warning(
                'Failed to set passwordResetRequired on breached user ' . $user->id . ': ' . $e->getMessage(),
                'password-policy',
            );
        } finally {
            $projectConfig->muteEvents = $previousMute;
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

        // 3. Audit-log entry — gated to Enterprise installs that have audit
        //    logging enabled. Lite/Pro skip this branch.
        if ($this->getIsEnterprise() && $this->getSettings()->enableAuditLog) {
            $this->getAuditLog()->logEvent(
                userId: $user->id,
                event: 'breach_detected',
                outcome: 'warning',
            );
        }

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
     * Registers User index integration: condition rules and bulk action.
     *
     * Condition rules allow filtering users by password status in
     * the Users index. Bulk action enables force-reset on selected users.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _registerUserIndexIntegration(): void
    {
        // Condition rules for user filtering
        Event::on(
            UserCondition::class,
            UserCondition::EVENT_REGISTER_CONDITION_RULES,
            function(RegisterConditionRulesEvent $event) {
                $event->conditionRules[] = PasswordExpiredConditionRule::class;
                $event->conditionRules[] = PasswordResetRequiredConditionRule::class;
                $event->conditionRules[] = PasswordNeverChangedConditionRule::class;
            }
        );

        // Bulk action for force password reset
        Event::on(
            User::class,
            User::EVENT_REGISTER_ACTIONS,
            function(RegisterElementActionsEvent $event) {
                if ($this->getIsPro()) {
                    $event->actions[] = ForcePasswordReset::class;
                }
            }
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
