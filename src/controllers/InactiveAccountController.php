<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Craft;
use craft\helpers\UrlHelper;
use craft\web\Controller;
use craftpulse\passwordpolicy\base\RequiresEditionTrait;
use craftpulse\passwordpolicy\enums\InactiveAction;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class InactiveAccountController
 *
 * Read-only CP surface for the Feature 5 inactive-account report — lists the
 * dormant accounts the scan would flag, with last-activity + days-inactive.
 *
 * The suspend / notify ACTIONS run via the operator-scheduled scan cron
 * (`password-policy/inactive/scan`), not a CP write button — so this
 * controller has no write actions and no CSRF-protected mutations. It is a
 * pure view surface gated behind `pp:inactive-view`.
 *
 * Edition gate: Pro-only, applied through
 * {@see RequiresEditionTrait::requireProEdition()}, which throws
 * {@see NotFoundHttpException} — 404, never 403, per the HTTP-controller half
 * of the plugin's edition-gate convention. The report doesn't exist below Pro
 * and the nav never offered it, so the URL behaves like any other nonexistent
 * route. The `ForbiddenHttpException` this controller also throws is the
 * `pp:inactive-view` permission denial, which is a different axis.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class InactiveAccountController extends Controller
{
    // Traits
    // =========================================================================

    use RequiresEditionTrait;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws ForbiddenHttpException if the user lacks `pp:inactive-view`
     * @throws NotFoundHttpException if the edition is below Pro
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();
        $this->requireProEdition();

        $this->requirePermission('pp:inactive-view');

        return true;
    }

    /**
     * Renders the inactive-account report — the dormant accounts the scan
     * would flag at the configured threshold, most-stale first.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();

        $report = $settings->inactiveAccountsEnabled
            ? $plugin->getInactiveAccounts()->getInactiveReport($settings->inactiveThresholdDays)
            : [];

        $pluginName = 'Password Policy';
        $title = Craft::t('password-policy', 'Inactive accounts');

        return $this->renderTemplate('password-policy/_inactive/index', [
            'pluginName' => $pluginName,
            'title' => $title,
            'docTitle' => "{$pluginName} - {$title}",
            'crumbs' => [
                [
                    'label' => $pluginName,
                    'url' => UrlHelper::cpUrl('password-policy'),
                ],
            ],
            'enabled' => $settings->inactiveAccountsEnabled,
            'thresholdDays' => $settings->inactiveThresholdDays,
            'action' => InactiveAction::tryFrom($settings->inactiveAction) ?? InactiveAction::Report,
            'report' => $report,
        ]);
    }
}
