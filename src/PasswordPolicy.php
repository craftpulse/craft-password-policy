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
use craft\elements\User;
use craft\events\DefineRulesEvent;
use craft\events\RegisterComponentTypesEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\events\RegisterUserPermissionsEvent;
use craft\events\TemplateEvent;
use craft\helpers\ArrayHelper;
use craft\helpers\Json;
use craft\log\MonologTarget;
use craft\services\UserPermissions;
use craft\services\Utilities;
use craft\web\twig\variables\CraftVariable;
use craft\web\UrlManager;
use craft\web\View;
use craftpulse\passwordpolicy\assetbundles\passwordpolicy\PasswordPolicyAsset;
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

    // Static Properties
    // =========================================================================

    /**
     * @var ?PasswordPolicy
     */
    public static ?PasswordPolicy $plugin = null;

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public string $schemaVersion = '1.0.0';

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

    /**
     * Sensitive keys that must never appear in log output. Stripped from
     * `$params` in {@see self::log()} before encoding.
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
        // Strip sensitive keys before any logging occurs. Defense-in-depth
        // for any consumer (or future plugin code) that calls log() with
        // password-bearing params — keys listed in SENSITIVE_LOG_KEYS never
        // reach the log destination.
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

        $editableSettings = true;
        $general = Craft::$app->getConfig()->getGeneral();

        if (!$general->allowAdminChanges) {
            $editableSettings = false;
        }

        if ($currentUser->can('pp:settings') && $editableSettings) {
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

        $this->_registerUserPermissions();
        $this->_registerUtilities();
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
                        'password-policy/plugins/password-policy' => 'password-policy/settings/edit',
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
