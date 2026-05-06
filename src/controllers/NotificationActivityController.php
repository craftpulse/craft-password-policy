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
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\NotificationActivityService;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class NotificationActivityController
 *
 * CP controller behind the `Notifications → Activity` subnav and the
 * per-row View / Resend actions. Read paths route through
 * {@see NotificationActivityService}; the resend write path delegates
 * to {@see \craftpulse\passwordpolicy\services\NotificationService::resend()}.
 *
 * Pro-gated (403 on Lite — the Notifications subnav itself is Pro-
 * gated, this is defense-in-depth) and permission-gated on
 * `pp:notification-templates-manage`. The capture side of the activity
 * surface (`NotificationService` writing rows on every send attempt)
 * runs on every edition; the read surface gates exposure.
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
     * Renders the activity index. Reads the filter set off the query
     * string (so URLs are linkable / shareable / bookmarkable),
     * paginates against `NotificationActivityService::paginated()`,
     * and hands the rows + pagination metadata to the index template.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $request = Craft::$app->getRequest();

        $filters = [
            'userId' => (string)$request->getQueryParam('userId', ''),
            'notificationType' => (string)$request->getQueryParam('type', ''),
            'status' => (string)$request->getQueryParam('status', ''),
            'siteId' => (string)$request->getQueryParam('siteId', ''),
            'dateFrom' => (string)$request->getQueryParam('dateFrom', ''),
            'dateTo' => (string)$request->getQueryParam('dateTo', ''),
        ];

        $page = max(1, (int)$request->getQueryParam('page', 1));
        $perPage = NotificationActivityService::DEFAULT_PAGE_SIZE;

        $service = PasswordPolicy::$plugin->getNotificationActivity();
        $result = $service->paginated($filters, $page, $perPage);

        return $this->renderTemplate('password-policy/_notifications/activity/index', [
            'rows' => $result['rows'],
            'total' => $result['total'],
            'page' => $page,
            'perPage' => $perPage,
            'pageCount' => max(1, (int)ceil($result['total'] / $perPage)),
            'filters' => $filters,
            'knownTypes' => $service->knownTypes(),
            'statusOptions' => [
                NotificationStatus::Sent->value => NotificationStatus::Sent->label(),
                NotificationStatus::Failed->value => NotificationStatus::Failed->label(),
            ],
        ]);
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
        $row = PasswordPolicy::$plugin->getNotificationActivity()->getById($id);

        if ($row === null) {
            throw new NotFoundHttpException(
                Craft::t('password-policy', 'Notification log row not found.')
            );
        }

        $resentFrom = $row->resentFromId !== null
            ? PasswordPolicy::$plugin->getNotificationActivity()->getById($row->resentFromId)
            : null;

        return $this->renderTemplate('password-policy/_notifications/activity/_detail', [
            'row' => $row,
            'resentFrom' => $resentFrom,
            'recipientUser' => Craft::$app->getUsers()->getUserById($row->userId),
        ]);
    }

    /**
     * Resends a previously-logged notification. Re-renders the
     * template fresh — admin may have edited the template since the
     * original send — and writes a new row linked to the original
     * via `resentFromId`. Bypasses the dedup gate: the admin's click
     * is an explicit override.
     *
     * Returns 400 when the row's `notificationType` isn't resendable
     * (mailer-key sources like `new_device` or `admin_alert_*` need
     * the original event payload, which we don't snapshot).
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

        $row = PasswordPolicy::$plugin->getNotificationActivity()->getById($id);

        if ($row === null) {
            throw new NotFoundHttpException(
                Craft::t('password-policy', 'Notification log row not found.')
            );
        }

        try {
            $dispatched = PasswordPolicy::$plugin->getNotification()->resend($row);
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
}
