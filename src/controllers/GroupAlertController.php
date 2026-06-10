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
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

/**
 * Class GroupAlertController
 *
 * Handles the CP editor for Feature 3 per-group alert subscriptions — the
 * page rendered at `password-policy/notifications/group-alerts` plus the
 * diff-on-save write action behind it. Routes a copy of `breach_detected` /
 * `new_device` alerts to a group-designated security contact.
 *
 * Pro-gated (403 on Lite). Permission-gated on
 * `pp:notification-templates-manage` — managing who gets alerted is a
 * notification-management concern, so the editor reuses the existing
 * Notifications-area permission rather than minting a new one.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupAlertController extends Controller
{
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
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();

        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new ForbiddenHttpException('Per-group alerts require the Pro edition.');
        }

        $this->requirePermission('pp:notification-templates-manage');

        return true;
    }

    /**
     * Renders the per-group alert editor — one editable-table row per
     * (group, event, recipient, enabled) subscription.
     *
     * @return Response
     *
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $plugin = PasswordPolicy::$plugin;
        $subscriptions = $plugin->getGroupAlerts()->getAllSubscriptions();

        $groupOptions = [];
        foreach (Craft::$app->getUserGroups()->getAllGroups() as $group) {
            $groupOptions[(string)$group->id] = $group->name;
        }

        $eventOptions = [
            'breach_detected' => Craft::t('password-policy', 'Breach detected (HIBP-on-login)'),
            'new_device' => Craft::t('password-policy', 'New device'),
        ];

        $pluginName = 'Password Policy';
        $templateTitle = Craft::t('password-policy', 'Group alerts');

        return $this->renderTemplate('password-policy/_notifications/group-alerts', [
            'pluginName' => $pluginName,
            'title' => $templateTitle,
            'docTitle' => "{$pluginName} - {$templateTitle}",
            'crumbs' => [
                [
                    'label' => $pluginName,
                    'url' => UrlHelper::cpUrl('password-policy'),
                ],
            ],
            'subscriptions' => $subscriptions,
            'groupOptions' => $groupOptions,
            'eventOptions' => $eventOptions,
        ]);
    }

    /**
     * Saves the subscription set from an EditableTable POST. The whole table
     * state is submitted as
     * `subscriptions[<rowId>][<col>] = '<value>'` — `GroupAlertService`
     * applies blocklist-style diff-on-save (kept rows survive, removed rows
     * delete, new rows insert).
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();

        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new ForbiddenHttpException('Per-group alerts require the Pro edition.');
        }

        /** @var array<int|string, array<string, mixed>> $rows */
        $rows = (array)Craft::$app->getRequest()->getBodyParam('subscriptions', []);

        PasswordPolicy::$plugin->getGroupAlerts()->saveSubscriptions($rows);

        PasswordPolicy::$plugin->log('Per-group alert subscriptions updated [by "{username}"]');

        $this->setSuccessFlash(
            Craft::t('password-policy', 'Group alerts saved.'),
        );

        return $this->redirectToPostedUrl();
    }
}
