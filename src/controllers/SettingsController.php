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
use craft\helpers\Queue;
use craft\helpers\UrlHelper;
use craft\web\Controller;
use craft\web\UrlManager;
use craftpulse\passwordpolicy\jobs\SeedBlocklist;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
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
    // Const Properties
    // =========================================================================

    /**
     * Valid settings sections for routing.
     *
     * @var string[]
     */
    private const VALID_SECTIONS = [
        'configuration',
        'rules',
        'retention',
        'history',
        'validators',
        'groups',
        'audit',
    ];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     */
    public function beforeAction($action): bool
    {
        $this->requireAdmin();

        return parent::beforeAction($action);
    }

    /**
     * Renders a settings section.
     *
     * When allowAdminChanges is disabled, the page renders in read-only mode
     * so admins can still view the active policy.
     *
     * @param string $section
     * @return Response
     *
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionEdit(string $section = 'configuration'): Response
    {
        $currentUser = Craft::$app->getUser()->getIdentity();
        if (!$currentUser->can('pp:settings')) {
            throw new ForbiddenHttpException('You do not have permission to view the Password Policy settings.');
        }

        if (!in_array($section, self::VALID_SECTIONS, true)) {
            throw new NotFoundHttpException('Invalid settings section.');
        }

        $general = Craft::$app->getConfig()->getGeneral();
        $readOnly = !$general->allowAdminChanges;

        $plugin = PasswordPolicy::$plugin;
        $pluginName = 'Password Policy';
        $templateTitle = Craft::t('password-policy', 'Settings');

        $variables = [
            'fullPageForm' => !$readOnly,
            'pluginName' => $pluginName,
            'title' => $templateTitle,
            'docTitle' => "{$pluginName} - {$templateTitle}",
            'crumbs' => [
                [
                    'label' => $pluginName,
                    'url' => UrlHelper::cpUrl('password-policy'),
                ],
            ],
            'settings' => $plugin->getSettings(),
            'readOnly' => $readOnly,
            'isPro' => $plugin->getIsPro(),
            'isEnterprise' => $plugin->getIsEnterprise(),
        ];

        return $this->renderTemplate("password-policy/_settings/{$section}", $variables);
    }

    /**
     * Saves the plugin settings.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     */
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();

        $currentUser = Craft::$app->getUser()->getIdentity();
        if (!$currentUser->can('pp:settings')) {
            throw new ForbiddenHttpException('You do not have permission to edit the Password Policy settings.');
        }
        $general = Craft::$app->getConfig()->getGeneral();
        if (!$general->allowAdminChanges) {
            throw new ForbiddenHttpException('Unable to edit Password Policy plugin settings because admin changes are disabled in this environment.');
        }

        $pluginHandle = Craft::$app->getRequest()->getRequiredBodyParam('pluginHandle');
        $plugin = Craft::$app->getPlugins()->getPlugin($pluginHandle);
        $submittedSettings = Craft::$app->getRequest()->getBodyParam('settings', []);

        if ($plugin === null) {
            throw new NotFoundHttpException('Plugin not found');
        }

        // Merge with existing settings — each section only submits its own fields,
        // Craft's savePluginSettings() only persists submitted keys to project config
        /** @var PasswordPolicy $plugin */
        $existingSettings = $plugin->getSettings()->getAttributes();
        $oldCheckCommonPasswords = $existingSettings['checkCommonPasswords'] ?? false;
        $settings = array_merge($existingSettings, $submittedSettings);

        // Strip edition-gated settings on lower editions
        /** @var PasswordPolicy $plugin */
        if (!$plugin->getIsPro()) {
            unset(
                $settings['passwordHistoryCount'],
                $settings['passwordHistoryExpiryDays'],
                $settings['checkSequentialChars'],
                $settings['checkRepeatedChars'],
                $settings['checkContextual'],
                $settings['checkCommonPasswords'],
                $settings['complexityMode'],
                $settings['minimumCharacterTypes'],
                $settings['enablePerGroupPolicies'],
                $settings['expiryReminderDays'],
                $settings['notificationLogRetentionDays'],
            );
        }
        if (!$plugin->getIsEnterprise()) {
            unset(
                $settings['enableAuditLog'],
                $settings['auditLogRetentionDays'],
                $settings['enableNewDeviceAlerts'],
                $settings['deviceRetentionDays'],
                $settings['adminAlertEmail'],
                $settings['adminAlertEvents'],
                $settings['siemEnabled'],
                $settings['siemDestinationType'],
                $settings['siemEndpointUrl'],
                $settings['siemAuthType'],
                $settings['siemAuthToken'],
                $settings['siemCustomHeaders'],
                $settings['siemIpHandling'],
                $settings['siemDeviceHandling'],
                $settings['webhooksEnabled'],
                $settings['webhooks'],
                $settings['apiEnabled'],
            );
        }

        if (!Craft::$app->getPlugins()->savePluginSettings($plugin, $settings)) {
            Craft::$app->getSession()->setError(Craft::t('app', "Couldn't save plugin settings."));

            /** @var UrlManager $urlManager */
            $urlManager = Craft::$app->getUrlManager();
            $urlManager->setRouteParams([
                'plugin' => $plugin,
            ]);

            return null;
        }

        // Auto-seed blocklist when "Block common passwords" is toggled on with an empty blocklist
        $this->_maybeSeedBlocklist($oldCheckCommonPasswords, $settings);

        Craft::$app->getSession()->setNotice(Craft::t('app', 'Plugin settings saved.'));

        return $this->redirectToPostedUrl();
    }

    // Private Methods
    // =========================================================================

    /**
     * Pushes a blocklist seed job when the common passwords toggle is enabled
     * and the blocklist is empty.
     *
     * @param mixed $oldValue The previous checkCommonPasswords value
     * @param array $newSettings The merged settings after save
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _maybeSeedBlocklist(mixed $oldValue, array $newSettings): void
    {
        $newValue = $newSettings['checkCommonPasswords'] ?? false;

        if (!$newValue || $oldValue) {
            return;
        }

        if (PasswordPolicy::$plugin->getBlocklist()->getCommonCount() > 0) {
            return;
        }

        Queue::push(new SeedBlocklist());

        Craft::$app->getSession()->setNotice(
            Craft::t('password-policy', 'Common password blocklist will be seeded in the background.'),
        );
    }
}
