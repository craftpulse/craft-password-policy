<?php
/**
 * Password Policy plugin for Craft CMS 3.x.
 *
 * Enforce stronger passwords on your users.
 *
 * @link      https://percipio.london
 *
 * @copyright Copyright (c) 2020 Percipio Global Ltd.
 */

namespace percipioglobal\passwordpolicy;

use Craft;
use craft\base\Plugin;
use craft\elements\User;
use craft\services\Plugins;
use percipioglobal\passwordpolicy\assetbundles\PasswordPolicy\PasswordPolicyAsset;
use percipioglobal\passwordpolicy\models\Settings;
use percipioglobal\passwordpolicy\services\PasswordService;
use yii\base\Event;
use yii\base\ModelEvent;

/**
 * Craft plugins are very much like little applications in and of themselves. We’ve made
 * it as simple as we can, but the training wheels are off. A little prior knowledge is
 * going to be required to write a plugin.
 *
 * For the purposes of the plugin docs, we’re going to assume that you know PHP and SQL,
 * as well as some semi-advanced concepts like object-oriented programming and PHP namespaces.
 *
 * https://craftcms.com/docs/plugins/introduction
 *
 * @author    Percipio Global Ltd.
 *
 * @since     1.0.0
 *
 * @property  Settings $settings
 * @property  PasswordService $passwordService
 *
 * @method    Settings getSettings()
 */
class PasswordPolicy extends Plugin
{
    // Static Properties
    // =========================================================================

    /**
     * Static property that is an instance of this plugin class so that it can be accessed via
     * PasswordPolicy::$plugin.
     *
     * @var PasswordPolicy
     */
    public static $plugin;

    // Public Properties
    // =========================================================================

    /**
     * To execute your plugin’s migrations, you’ll need to increase its schema version.
     *
     * @var string
     */
    public $schemaVersion = '1.0.0';

    // Public Methods
    // =========================================================================

    /**
     * Set our $plugin static property to this class so that it can be accessed via
     * PasswordPolicy::$plugin.
     *
     * Called after the plugin class is instantiated; do any one-time initialization
     * here such as hooks and events.
     *
     * If you have a '/vendor/autoload.php' file, it will be loaded for you automatically;
     * you do not need to load it in your init() method.
     */
    public function init()
    {
        parent::init();
        self::$plugin = $this;

        $this->name = Craft::t('password-policy', 'Password Policy');

        if (Craft::$app->request->isCpRequest) {
            Craft::$app->view->registerAssetBundle(PasswordPolicyAsset::class);
        }

        Event::on(
            User::class,
            User::EVENT_BEFORE_VALIDATE,
            function (ModelEvent $event) {
                if ($event->sender->newPassword) {
                    $errors = $this->passwordService->getValidationErrors($event->sender->newPassword);
                    $event->isValid = count($errors) === 0;

                    if (!$event->isValid) {
                        /** @var User $user */
                        $user = $event->sender;
                        foreach ($errors as $error) {
                            $user->addError('newPassword', $error);
                        }
                    }
                }
            }
        );
    }

    // Protected Methods
    // =========================================================================

    /**
     * Creates and returns the model used to store the plugin’s settings.
     *
     * @return \craft\base\Model|null
     */
    protected function createSettingsModel()
    {
        return new Settings();
    }

    /**
     * Returns the rendered settings HTML, which will be inserted into the content
     * block on the settings page.
     *
     * @return string The rendered settings HTML
     */
    protected function settingsHtml(): string
    {
        return Craft::$app->view->renderTemplate(
            'password-policy/settings',
            [
                'settings' => $this->getSettings(),
            ]
        );
    }
}
