<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Craft;
use craft\helpers\UrlHelper;
use craft\web\Controller;

use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\Response;

/**
 * Class SettingsController
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class SettingsController extends Controller
{
    /**
     * @inheritdoc
     */
    public function beforeAction($action): bool
    {
        $this->requireAdmin();

        return parent::beforeAction($action);
    }

    /**
     * @return Response|null
     */
    public function actionEdit(): ?Response
    {
        // Ensure they have permission to edit the plugin settings
        $currentUser = Craft::$app->getUser()->getIdentity();
        if (!$currentUser->can('pp:settings')) {
            throw new ForbiddenHttpException('You do not have permission to edit the Password Policy settings.');
        }
        $general = Craft::$app->getConfig()->getGeneral();
        if (!$general->allowAdminChanges) {
            throw new ForbiddenHttpException('Unable to edit Password Policy plugin settings because admin changes are disabled in this environment.');
        }

        // Edit the plugin settings
        $variables = [];
        $pluginName = 'Password Policy';
        $templateTitle = Craft::t('password-policy', 'Plugin settings');

        $variables['fullPageForm'] = true;
        $variables['pluginName'] = $pluginName;
        $variables['title'] = $templateTitle;
        $variables['docTitle'] = "{$pluginName} - {$templateTitle}";
        $variables['crumbs'] = [
            [
                'label' => $pluginName,
                'url' => UrlHelper::cpUrl('password-policy'),
            ],
            [
                'label' => $templateTitle,
                'url' => UrlHelper::cpUrl('password-policy/plugin'),
            ],
        ];
        $variables['settings'] = PasswordPolicy::$plugin->settings;

        return $this->renderTemplate('password-policy/_settings', $variables);
    }

    /**
     * Saves the plugin settings
     */
    public function actionSave(): ?Response
    {
        // Ensure they have permission to edit the plugin settings
        $currentUser = Craft::$app->getUser()->getIdentity();
        if (!$currentUser->can('pp:settings')) {
            throw new ForbiddenHttpException('You do not have permission to edit the Password Policy settings.');
        }
        $general = Craft::$app->getConfig()->getGeneral();
        if (!$general->allowAdminChanges) {
            throw new ForbiddenHttpException('Unable to edit Password Policy plugin settings because admin changes are disabled in this environment.');
        }

        // Save the plugin settings
        $this->requirePostRequest();
        $pluginHandle = Craft::$app->getRequest()->getRequiredBodyParam('pluginHandle');
        $plugin = Craft::$app->getPlugins()->getPlugin($pluginHandle);
        $settings = Craft::$app->getRequest()->getBodyParam('settings', []);

        if ($plugin === null) {
            throw new NotFoundHttpException('Plugin not found');
        }

        if (!Craft::$app->getPlugins()->savePluginSettings($plugin, $settings)) {
            Craft::$app->getSession()->setError(Craft::t('app', "Couldn't save plugin settings."));

            // Send the redirect back to the template
            /** @var UrlManager $urlManager */
            $urlManager = Craft::$app->getUrlManager();
            $urlManager->setRouteParams([
                'plugin' => $plugin,
            ]);

            return null;
        }

        Craft::$app->getSession()->setNotice(Craft::t('app', 'Plugin settings saved.'));

        return $this->redirectToPostedUrl();
    }
}
