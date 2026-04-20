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
use craft\events\DefineRulesEvent;
use craft\events\ModelEvent;
use craft\events\RegisterComponentTypesEvent;
use craft\events\RegisterConditionRulesEvent;
use craft\events\RegisterElementActionsEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\events\RegisterUserPermissionsEvent;
use craft\events\TemplateEvent;
use craft\helpers\ArrayHelper;
use craft\helpers\ElementHelper;
use craft\helpers\Json;
use craft\log\MonologTarget;
use craft\services\Gc;
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
    public string $schemaVersion = '2.0.0';

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
     * Returns whether the plugin is running the Lite edition.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsLite(): bool
    {
        return true;
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
                $variable->set('passwordpolicy', [
                    'class' => PasswordPolicyVariable::class,
                    'viteService' => $this->vite,
                ]);
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

                foreach (UserRules::defineRules() as $rule) {
                    $event->rules[] = $rule;
                }
            }
        );

        // Password history: cache plaintext before save
        $this->_registerPasswordHistoryListeners();

        // Craft security event listeners (Enterprise audit logging)
        $this->_registerCraftSecurityListeners();

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
     * Registers Craft GC hook to purge old data from all plugin tables.
     *
     * Ensures GDPR-compliant automatic data minimization without
     * requiring manual cron setup.
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
            function() {
                $settings = $this->getSettings();

                // Notification log (Pro+)
                if ($this->getIsPro()) {
                    $this->getNotification()->pruneOldEntries(
                        $settings->notificationLogRetentionDays,
                    );
                }

                // Password history TTL (Pro)
                if ($this->getIsPro() && $settings->passwordHistoryCount > 0) {
                    $threshold = (new \DateTime())
                        ->modify("-{$settings->passwordHistoryExpiryDays} days")
                        ->format('Y-m-d H:i:s');

                    \Craft::$app->getDb()->createCommand()
                        ->delete('{{%passwordpolicy_password_history}}', [
                            '<', 'dateCreated', $threshold,
                        ])
                        ->execute();
                }

                // Audit log (Enterprise)
                if ($this->getIsEnterprise() && $settings->enableAuditLog) {
                    $this->getAuditLog()->purgeOldEntries(
                        $settings->auditLogRetentionDays,
                    );
                }
            }
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
