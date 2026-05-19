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
use craftpulse\passwordpolicy\enums\PolicyPreset;
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
        'presets',
        'audit',
    ];

    /**
     * Preset fields that get written to the global SettingsModel by
     * `actionApplyPreset()`. Matches the union of fields any of the
     * five `PolicyPreset::_apply*()` methods touch. Fields not in this
     * list are left untouched even if the preset model has a non-null
     * value for them.
     *
     * @var string[]
     */
    private const PRESET_APPLIED_FIELDS = [
        'minLength',
        'maxLength',
        'cases',
        'numbers',
        'symbols',
        'hibp',
        'hibpFailMode',
        'checkCommonPasswords',
        'passwordHistoryCount',
        'expiryAmount',
        'expiryPeriod',
    ];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Admins always get through the gate so the read-only settings views
     * keep working when `allowAdminChanges = false` (the standard
     * production posture). Write actions (`actionSave`, `actionApplyPreset`)
     * re-check `allowAdminChanges` themselves and throw with a
     * plugin-specific message.
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     */
    public function beforeAction($action): bool
    {
        $this->requireAdmin(false);

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
                $settings['checkSequentialChars'],
                $settings['checkRepeatedChars'],
                $settings['checkContextual'],
                $settings['complexityMode'],
                $settings['minimumCharacterTypes'],
                $settings['enablePerGroupPolicies'],
                $settings['notificationLogRetentionDays'],
                $settings['enableHibpOnLogin'],
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
                $settings['siemForwardEventClasses'],
                $settings['siemCircuitCooldownSeconds'],
                $settings['siemCircuitFailureThreshold'],
                $settings['webhooksEnabled'],
                $settings['webhooks'],
                $settings['webhookForwardEventClasses'],
                $settings['webhookCircuitCooldownSeconds'],
                $settings['webhookCircuitFailureThreshold'],
                $settings['webhookSecretGracePeriodHours'],
                $settings['auditExportFilesystem'],
                $settings['auditPiiKey'],
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

    /**
     * Applies a `PolicyPreset` to the global plugin settings.
     *
     * Pro+ only. Presets shorthand a compliance-framework conformance
     * promise (NIST 800-63B Rev. 4, OWASP ASVS L1, PCI-DSS v4.0, CIS
     * Controls v8, Strict Enterprise). That promise leans on Pro-only
     * machinery (sequential / repeated / contextual validators for
     * Strict; per-group policy resolution for everything else) and is
     * a Pro value prop — Lite installs configure rules manually.
     *
     * Defense-in-depth: the UI hides the Apply buttons on Lite via the
     * `isPro` template flag, but the controller refuses the apply
     * regardless so a crafted POST can't bypass the gate.
     *
     * Per-group preset application uses a separate path through
     * `PolicyController` and the named-policy CRUD flow.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionApplyPreset(): ?Response
    {
        $this->requirePostRequest();

        $currentUser = Craft::$app->getUser()->getIdentity();
        if (!$currentUser->can('pp:settings')) {
            throw new ForbiddenHttpException('You do not have permission to edit the Password Policy settings.');
        }
        $general = Craft::$app->getConfig()->getGeneral();
        if (!$general->allowAdminChanges) {
            throw new ForbiddenHttpException('Unable to apply preset because admin changes are disabled in this environment.');
        }

        $plugin = PasswordPolicy::$plugin;
        if (!$plugin->getIsPro()) {
            throw new ForbiddenHttpException('Compliance presets require the Pro edition.');
        }

        $presetValue = Craft::$app->getRequest()->getRequiredBodyParam('preset');
        $preset = PolicyPreset::tryFrom($presetValue);
        if ($preset === null) {
            throw new BadRequestHttpException('Unknown preset.');
        }

        $presetPolicy = $preset->toGroupPolicy();
        $existingSettings = $plugin->getSettings()->getAttributes();
        $settings = $existingSettings;

        foreach (self::PRESET_APPLIED_FIELDS as $field) {
            if (property_exists($presetPolicy, $field) && $presetPolicy->$field !== null) {
                $settings[$field] = $presetPolicy->$field;
            }
        }

        if (!Craft::$app->getPlugins()->savePluginSettings($plugin, $settings)) {
            Craft::$app->getSession()->setError(
                Craft::t('password-policy', "Couldn't apply the {preset} preset.", ['preset' => $preset->label()]),
            );

            return null;
        }

        Craft::$app->getSession()->setNotice(
            Craft::t('password-policy', '{preset} preset applied to global settings.', ['preset' => $preset->label()]),
        );

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
