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
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class NotificationActivityController
 *
 * CP controller behind the `Notifications → Activity` subnav and the
 * per-row view / resend actions.
 *
 * The index action renders a thin Twig template that extends
 * `_layouts/elementindex` against {@see NotificationLogElement} — the
 * native element-index renderer handles sources sidebar, status
 * filtering, pagination, sort, bulk actions (Resend, Delete, Restore),
 * and search. The controller wraps the render so the stable subnav URL
 * (`/admin/password-policy/notifications/activity`) stays a contract;
 * breadcrumbs / permission gates live here.
 *
 * Pro-gated (403 on Lite — the Notifications subnav itself is Pro-
 * gated, this is defense-in-depth) and permission-gated on
 * `pp:notification-templates-manage`. The capture side of the
 * activity surface (`NotificationService` writing rows on every send
 * attempt) runs on every edition; the read surface gates exposure.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationActivityController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int|string>|bool|int CP-only — every action requires
     *     an authenticated admin session.
     */
    protected array|bool|int $allowAnonymous = false;

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
            throw new ForbiddenHttpException(
                Craft::t('password-policy', 'The notifications activity surface requires the Pro edition.')
            );
        }

        $this->requirePermission('pp:notification-templates-manage');

        return true;
    }

    /**
     * Renders the activity index via the native element-index renderer.
     * The template extends `_layouts/elementindex` and points Craft at
     * the `NotificationLogElement` class — sources sidebar, status
     * filter, pagination, sort, bulk actions, search all come from the
     * native element-index plumbing.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        return $this->renderTemplate('password-policy/_notifications/activity/index');
    }

    /**
     * Resends a previously-logged notification. Re-renders the
     * template fresh — admin may have edited the template since the
     * original send — and writes a new element row linked to the
     * original via `resentFromId`. Bypasses the dedup gate: the
     * admin's click is an explicit override.
     *
     * Returns 400 when the row's `notificationType` isn't resendable
     * (mailer-key sources like `new_device` or `admin_alert_*` need
     * the original event payload, which we don't snapshot).
     *
     * Element bulk-resend goes through `ResendNotification` instead of
     * this endpoint; this is kept as the single-row write path
     * targeted by the detail screen's Resend button.
     *
     * @return Response
     *
     * @throws BadRequestHttpException when the row isn't resendable
     * @throws NotFoundHttpException when the row doesn't exist
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionResend(): Response
    {
        $this->requirePostRequest();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('id');

        $element = PasswordPolicy::$plugin->getNotificationActivity()->getById($id);

        if ($element === null) {
            throw new NotFoundHttpException(
                Craft::t('password-policy', 'Notification log row not found.')
            );
        }

        try {
            $dispatched = PasswordPolicy::$plugin->getNotification()->resend($element);
        } catch (Throwable $e) {
            return $this->asFailure(
                Craft::t('password-policy', 'Couldn’t resend notification: {error}', [
                    'error' => $e->getMessage(),
                ]),
            );
        }

        if (!$dispatched) {
            return $this->asFailure(
                Craft::t(
                    'password-policy',
                    'This notification type isn’t resendable — the original event payload isn’t recorded.',
                ),
            );
        }

        return $this->asSuccess(
            Craft::t('password-policy', 'Notification queued for resend.'),
            data: [],
            redirect: UrlHelper::cpUrl('password-policy/notifications/activity'),
        );
    }

    /**
     * Renders the detail view for a single notification log row.
     * Surfaces full subject + body + error message (if failed) +
     * resend chain pointer.
     *
     * @param int $id
     * @return Response
     *
     * @throws NotFoundHttpException when the row doesn't exist
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionView(int $id): Response
    {
        $element = PasswordPolicy::$plugin->getNotificationActivity()->getById($id);

        if ($element === null) {
            throw new NotFoundHttpException(
                Craft::t('password-policy', 'Notification log row not found.')
            );
        }

        $resentFrom = $element->resentFromId !== null
            ? PasswordPolicy::$plugin->getNotificationActivity()->getById($element->resentFromId)
            : null;

        $recipientUser = $element->userId !== null
            ? Craft::$app->getUsers()->getUserById($element->userId)
            : null;

        return $this->renderTemplate('password-policy/_notifications/activity/_detail', [
            'row' => $element,
            'resentFrom' => $resentFrom,
            'recipientUser' => $recipientUser,
        ]);
    }
}
