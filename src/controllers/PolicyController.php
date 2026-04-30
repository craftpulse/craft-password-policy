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
use craft\helpers\App;
use craft\helpers\Cp;
use craft\helpers\Html;
use craft\web\Controller;
use craftpulse\passwordpolicy\enums\PolicyPreset;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class PolicyController
 *
 * Handles CRUD operations for named password policies.
 * All actions require admin access and pp:settings permission.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyController extends Controller
{
    // Private Properties
    // =========================================================================

    /**
     * @var bool whether admin changes are disallowed in this environment
     */
    private bool $_readOnly = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        $viewActions = ['index', 'edit'];
        if (in_array($action->id, $viewActions, true)) {
            $this->requireAdmin(false);
        } else {
            $this->requireAdmin();
        }

        $this->_readOnly = !Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

        return parent::beforeAction($action);
    }

    /**
     * Renders the policies index page with VueAdminTable.
     *
     * @return Response
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $this->_requireSettingsPermission();
        $this->_requireProEdition();

        $plugin = PasswordPolicy::$plugin;
        $policies = $plugin->getPolicies()->getAllPolicies();

        // Build preset label mapping for display
        $presetLabels = [];
        foreach (PolicyPreset::cases() as $preset) {
            $presetLabels[$preset->value] = $preset->label();
        }

        return $this->renderTemplate('password-policy/_policies/_index', [
            'policies' => $policies,
            'presetLabels' => $presetLabels,
            'readOnly' => $this->_readOnly,
            'isPro' => $plugin->getIsPro(),
        ]);
    }

    /**
     * Renders the policy edit screen using asCpScreen().
     *
     * The optional `$policy` argument is injected by Craft's URL manager from
     * route params — set by `asModelFailure()` when validation fails. This
     * preserves user edits and per-field error messages on re-render.
     *
     * @param int|null $policyId the policy ID for existing policies
     * @param PolicyModel|null $policy the model from a failed save (route param)
     * @return Response
     *
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionEdit(?int $policyId = null, ?PolicyModel $policy = null): Response
    {
        $this->_requireSettingsPermission();
        $this->_requireProEdition();

        $plugin = PasswordPolicy::$plugin;

        if ($policy === null) {
            if ($policyId !== null) {
                $policy = $plugin->getPolicies()->getPolicyById($policyId);
                if ($policy === null) {
                    throw new NotFoundHttpException('Policy not found.');
                }
            } else {
                if ($this->_readOnly) {
                    throw new ForbiddenHttpException('Administrative changes are disallowed in this environment.');
                }
                $policy = new PolicyModel();
            }
        }

        $isNew = !$policy->id;
        $allGroups = Craft::$app->getUserGroups()->getAllGroups();
        $assignedGroupIds = $policy->getGroupIds();
        $globalSettings = $plugin->getSettings();

        $response = $this->asCpScreen()
            ->title($isNew ? Craft::t('password-policy', 'New Policy') : $policy->name)
            ->selectedSubnavItem('policies')
            ->addCrumb(
                Craft::t('password-policy', 'Password Policy'),
                'password-policy',
            )
            ->addCrumb(
                Craft::t('password-policy', 'Policies'),
                'password-policy/policies',
            )
            ->tabs([
                'general' => [
                    'label' => Craft::t('password-policy', 'General'),
                    'url' => '#general',
                ],
                'rules' => [
                    'label' => Craft::t('password-policy', 'Rules'),
                    'url' => '#rules',
                ],
                'lifecycle' => [
                    'label' => Craft::t('password-policy', 'Lifecycle'),
                    'url' => '#lifecycle',
                ],
            ])
            ->contentTemplate('password-policy/_policies/_edit', [
                'policy' => $policy,
                'allGroups' => $allGroups,
                'assignedGroupIds' => $assignedGroupIds,
                'globalSettings' => $globalSettings,
                'isPro' => $plugin->getIsPro(),
                'isNew' => $isNew,
                'readOnly' => $this->_readOnly,
            ]);

        if (!$this->_readOnly) {
            $response
                ->action('password-policy/policy/save')
                ->redirectUrl('password-policy/policies')
                ->saveShortcutRedirectUrl('password-policy/policies/{id}')
                ->additionalButtonsHtml(Html::tag('button', Craft::t('password-policy', 'Reset all to global'), [
                    'type' => 'button',
                    'id' => 'pp-reset-rules',
                    'class' => 'btn',
                ]));

            if (!$isNew) {
                $response->addAltAction(
                    Craft::t('app', 'Save and continue editing'),
                    [
                        'redirect' => 'password-policy/policies/{id}',
                        'shortcut' => true,
                        'retainScroll' => true,
                    ],
                );
            }
        }

        $noticeHtml = $this->_buildEditNoticeHtml($policy, $globalSettings);
        if ($noticeHtml !== null) {
            $response->noticeHtml($noticeHtml);
        }

        return $response;
    }

    /**
     * Saves a policy from POST data.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws \Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();
        $this->_requireSettingsPermission();
        $this->_requireAdminChanges();
        $this->_requireProEdition();

        $request = Craft::$app->getRequest();
        $policyId = $request->getBodyParam('policyId');

        $plugin = PasswordPolicy::$plugin;

        if ($policyId) {
            $policy = $plugin->getPolicies()->getPolicyById((int)$policyId);
            if ($policy === null) {
                throw new BadRequestHttpException("Invalid policy ID: $policyId");
            }
        } else {
            $policy = new PolicyModel();
        }

        $policy->name = $request->getBodyParam('name', '');
        $policy->handle = $request->getBodyParam('handle', '');
        $policy->preset = $request->getBodyParam('preset') ?: null;

        // Build settings from POST override fields
        $rawSettings = $request->getBodyParam('settings', []);
        $settings = $this->_normalizeSettings($rawSettings);
        $policy->setSettingsFromArray($settings);

        // checkboxSelectField submits a hidden empty value when nothing is checked —
        // coerce to array and drop empty entries.
        $groupIds = (array)$request->getBodyParam('groupIds', []);
        $groupIds = array_values(array_filter($groupIds, fn($id) => $id !== '' && $id !== null));

        if (!$plugin->getPolicies()->savePolicy($policy, $groupIds)) {
            return $this->asModelFailure(
                $policy,
                Craft::t('password-policy', "Couldn't save policy."),
                'policy',
            );
        }

        $globalSettings = $plugin->getSettings();
        if ($this->_hasMinLengthConflict($policy, $globalSettings)) {
            Craft::$app->getSession()->setNotice(Craft::t(
                'password-policy',
                "This policy's minimum length ({min}) exceeds the global maximum length ({max}). The global cap will be ignored at validation time when this policy applies.",
                [
                    'min' => (int)App::parseEnv((string)$policy->minLength),
                    'max' => (int)$globalSettings->maxLength,
                ],
            ));
        }

        return $this->asModelSuccess(
            $policy,
            Craft::t('password-policy', 'Policy saved.'),
            'policy',
        );
    }

    /**
     * Deletes a policy.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws \yii\db\Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionDelete(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireSettingsPermission();
        $this->_requireAdminChanges();
        $this->_requireProEdition();

        $id = Craft::$app->getRequest()->getRequiredBodyParam('id');
        PasswordPolicy::$plugin->getPolicies()->deletePolicy((int)$id);

        return $this->asSuccess();
    }

    /**
     * Reorders policies by sort order.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws \Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionReorder(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireSettingsPermission();
        $this->_requireAdminChanges();
        $this->_requireProEdition();

        $ids = Craft::$app->getRequest()->getRequiredBodyParam('ids');
        PasswordPolicy::$plugin->getPolicies()->reorderPolicies($ids);

        return $this->asSuccess();
    }

    // Private Methods
    // =========================================================================

    /**
     * Normalizes raw POST settings into typed values for the PolicyModel.
     *
     * Empty strings become null (inherit global). Lightswitch values are
     * cast to bool. Integer fields are cast to int.
     *
     * @param array<string, mixed> $raw the raw POST settings
     * @return array<string, mixed> the normalized settings
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _normalizeSettings(array $raw): array
    {
        /** @var string[] $intFields */
        $intFields = [
            'passwordHistoryCount',
            'expiryAmount',
            'minimumCharacterTypes',
        ];

        // minLength and maxLength may hold env references (e.g. `$PP_MIN_LENGTH`) —
        // PolicyModel registers EnvAttributeParserBehavior for both. Resolution
        // happens in beforeValidate, so the controller passes raw strings through
        // unchanged and only int-casts plain numeric values.
        /** @var string[] $envIntFields */
        $envIntFields = [
            'minLength',
            'maxLength',
        ];

        /** @var string[] $boolFields */
        $boolFields = [
            'cases',
            'numbers',
            'symbols',
            'hibp',
            'checkSequentialChars',
            'checkRepeatedChars',
            'checkContextual',
            'checkCommonPasswords',
        ];

        /** @var string[] $stringFields */
        $stringFields = [
            'hibpFailMode',
            'complexityMode',
            'expiryPeriod',
        ];

        $normalized = [];

        foreach ($intFields as $field) {
            if (isset($raw[$field]) && $raw[$field] !== '') {
                $normalized[$field] = (int)$raw[$field];
            }
        }

        foreach ($envIntFields as $field) {
            if (!isset($raw[$field]) || $raw[$field] === '') {
                continue;
            }
            $value = $raw[$field];
            // Numeric → int. Anything else (incl. `$VAR` / `@alias` references)
            // passes through as a string for the env parser to resolve.
            $normalized[$field] = is_numeric($value) ? (int)$value : (string)$value;
        }

        // Tri-state booleans: '1' = explicit on, '0' = explicit off, '' = inherit (not stored)
        foreach ($boolFields as $field) {
            if (!isset($raw[$field]) || $raw[$field] === '') {
                continue;
            }
            $normalized[$field] = $raw[$field] === '1';
        }

        foreach ($stringFields as $field) {
            if (!empty($raw[$field])) {
                $normalized[$field] = $raw[$field];
            }
        }

        // expiryPeriod is only meaningful with an expiryAmount
        if (!isset($normalized['expiryAmount'])) {
            unset($normalized['expiryPeriod']);
        }

        return $normalized;
    }

    /**
     * Returns true when the policy's explicit `minLength` exceeds the global
     * `maxLength` cap, which means the global cap will be dropped at merge
     * time for users this policy applies to.
     *
     * Both values must be positive — `maxLength = 0` is "no limit" globally,
     * and a null `minLength` on the policy means inherit (no conflict possible).
     *
     * `minLength` may hold an env reference (e.g. `$PP_MIN_LENGTH`) — resolve
     * via `App::parseEnv()` before comparing so the conflict still surfaces
     * when the policy is configured via env vars.
     *
     * @param PolicyModel $policy the policy being saved or viewed
     * @param SettingsModel $globalSettings the global plugin settings
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hasMinLengthConflict(PolicyModel $policy, SettingsModel $globalSettings): bool
    {
        if ($policy->minLength === null) {
            return false;
        }

        $policyMin = (int)App::parseEnv((string)$policy->minLength);
        $globalMax = (int)$globalSettings->maxLength;

        return $policyMin > 0
            && $globalMax > 0
            && $policyMin > $globalMax;
    }

    /**
     * Builds the noticeHtml string for the edit screen, combining the
     * read-only environment notice (when applicable) and the min/max
     * length conflict banner (when applicable).
     *
     * @param PolicyModel $policy the policy being viewed
     * @param SettingsModel $globalSettings the global plugin settings
     * @return string|null the combined notice HTML, or null when nothing to show
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildEditNoticeHtml(PolicyModel $policy, SettingsModel $globalSettings): ?string
    {
        $parts = [];

        if ($this->_hasMinLengthConflict($policy, $globalSettings)) {
            $message = Craft::t(
                'password-policy',
                "This policy's minimum length ({min}) exceeds the global maximum length ({max}). The global cap will be ignored at validation time when this policy applies.",
                [
                    'min' => (int)App::parseEnv((string)$policy->minLength),
                    'max' => (int)$globalSettings->maxLength,
                ],
            );
            $parts[] = Html::tag(
                'div',
                Html::tag('p', Html::encode($message)),
                ['class' => 'pp-conflict-banner'],
            );
        }

        if ($this->_readOnly) {
            $parts[] = Cp::readOnlyNoticeHtml();
        }

        if (empty($parts)) {
            return null;
        }

        return implode("\n", $parts);
    }

    /**
     * Requires that the current user has the pp:settings permission.
     *
     * @return void
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _requireSettingsPermission(): void
    {
        $this->requirePermission('pp:settings');
    }

    /**
     * Requires that admin changes are allowed in this environment.
     *
     * @return void
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _requireAdminChanges(): void
    {
        if ($this->_readOnly) {
            throw new ForbiddenHttpException(
                'Administrative changes are disallowed in this environment.',
            );
        }
    }

    /**
     * Requires that the plugin is running the Pro edition or higher.
     *
     * @return void
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _requireProEdition(): void
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new ForbiddenHttpException(
                'Named policies require the Pro edition.',
            );
        }
    }
}
