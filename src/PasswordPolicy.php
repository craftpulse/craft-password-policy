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
use craft\events\PluginEvent;
use craft\events\RegisterComponentTypesEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\events\RegisterUserPermissionsEvent;
use craft\events\TemplateEvent;
use craft\helpers\Json;
use craft\log\MonologTarget;
use craft\services\Plugins;
use craft\services\UserPermissions;
use craft\services\Utilities;
use craft\web\twig\variables\CraftVariable;
use craft\web\UrlManager;
use craft\web\View;

use craftpulse\passwordpolicy\assetbundles\passwordpolicy\PasswordPolicyAsset;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\rules\UserRules;
use craftpulse\passwordpolicy\services\PasswordService;
use craftpulse\passwordpolicy\services\RetentionService;
use craftpulse\passwordpolicy\utilities\RetentionUtility;
use craftpulse\passwordpolicy\variables\PasswordPolicyVariable;

use Monolog\Formatter\LineFormatter;

use nystudio107\pluginvite\services\VitePluginService;
use Psr\Log\LogLevel;
use yii\base\Event;
use yii\base\InvalidRouteException;
use yii\log\Dispatcher;
use yii\log\Logger;

/**
 * Class PasswordPolicy
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordPolicy extends Plugin
{
    // Traits
    // =========================================================================

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
     * @var mixed|object|null
     */
    public mixed $queue = null;

    /**
     * @var null|SettingsModel
     */
    public static ?SettingsModel $settings = null;

    /**
     * @inheritdoc
     */
    public static function config(): array
    {
        return [
            'components' => [
                'passwords' => PasswordService::class,
                'retention' => RetentionService::class,
                // Register the vite service
                // @TODO devServerPublic / devServerInternal / serverPublic would benefit of `.env` vars for local dev
                'vite' => [
                    'class' => VitePluginService::class,
                    'assetClass' => PasswordPolicyAsset::class,
                    'useDevServer' => true,
                    'devServerPublic' => 'http://localhost:3005',
                    'serverPublic' => 'http://localhost:8000',
                    'errorEntry' => 'src/js/PasswordPolicy.js',
                    'devServerInternal' => 'http://craft-password-policy-v5-buildchain-dev:3005',
                    'checkDevServer' => true,
                ],
            ],
        ];
    }

    public function init(): void
    {
        parent::init();
        self::$plugin = $this;

        $request = Craft::$app->getRequest();
        if ($request->getIsConsoleRequest()) {
            $this->controllerNamespace = 'craftpulse\passwordpolicy\console\controllers';
        }

        // Install our global evnet handlers
        $this->installEventHandlers();

        // Register control panel events
        if (Craft::$app->getRequest()->getIsCpRequest()) {
            $this->registerCpUrlRules();
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
     * Logs a message
     * @throws Throwable
     */
    public function log(string $message, array $params = [], int $type = Logger::LEVEL_INFO): void
    {
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
     * @throws InvalidRouteException
     */
    public function getSettingsResponse(): mixed
    {
        return Craft::$app->getResponse()->redirect('password-policy/settings');
    }

    /**
     * @inheritdoc
     * @throws Throwable
     */
    public function getCpNavItem(): ?array
    {
        $subNavs = [];
        $navItem = parent::getCpNavItem();
        $currentUser = Craft::$app->getUser()->getIdentity();

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

    /**
     * @inheritdoc
     */
    protected function settingsHtml(): ?string
    {
        return Craft::$app->getView()->renderTemplate(
            'password-policy/_settings',
            [ 'settings' => $this->getSettings() ]
        );
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    protected function createSettingsModel(): ?Model
    {
        return new SettingsModel();
    }

    /**
     * @return void
     */
    protected function installEventHandlers(): void
    {
        Event::on(
            Plugins::class,
            Plugins::EVENT_AFTER_SAVE_PLUGIN_SETTINGS,
            function(PluginEvent $event) {
                if ($event->plugin === $this) {
                    Craft::debug(
                        'Plugins::EVENT_AFTER_SAVE_PLUGIN_SETTINGS',
                        __METHOD__
                    );
                }
            }
        );

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
                self::$plugin->passwords->pwned('testtest');
                foreach (UserRules::defineRules() as $rule) {
                    $event->rules[] = $rule;
                }
            }
        );

        // Load asset before page template is rendered
        Event::on(
            View::class,
            View::EVENT_BEFORE_RENDER_PAGE_TEMPLATE,
            function(TemplateEvent $event) {
                // Get view
                $view = Craft::$app->getView();

                // Register Asset Bundle
                $view->registerAssetBundle(PasswordPolicyAsset::class);

                // Load Asset
                $this->vite->register('src/js/indicator.ts', false);
            }
        );

        $this->registerUserPermissions();
        $this->registerUtilities();
    }

    // Private Methods
    // =========================================================================

    /**
     * Registers CP URL rules event
     */
    private function registerCpUrlRules(): void
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
     * Registers user permissions
     */
    private function registerUserPermissions(): void
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

    private function registerUtilities(): void
    {
        if ($this->settings->retentionUtilities) {
            Event::on(Utilities::class, Utilities::EVENT_REGISTER_UTILITIES,
                function(RegisterComponentTypesEvent $event) {
                    $event->types[] = RetentionUtility::class;
                }
            );
        }
    }

    /**
     * Registers a custom log target
     *
     * @see LineFormatter::SIMPLE_FORMAT
     */
    private function registerLogTarget(): void
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
