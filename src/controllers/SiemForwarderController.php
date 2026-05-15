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
use craft\helpers\Cp;
use craft\web\Controller;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class SiemForwarderController
 *
 * CP CRUD for the SIEM forwarders index (G8). Edition-gated to
 * Enterprise on every action; permission-gated on `pp:siem-manage`.
 *
 * The controller is the third line of defense: subnav doesn't register
 * on Pro / Lite (in {@see PasswordPolicy::getCpNavItem()}); the
 * permission only registers on Enterprise (in
 * {@see PasswordPolicy::_registerUserPermissions()}); and this
 * controller's `beforeAction()` rejects anyone who slipped past those
 * (e.g. a bookmarked URL after an edition downgrade).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SiemForwarderController extends Controller
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
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();

        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            throw new ForbiddenHttpException(
                'SIEM forwarder management requires the Enterprise edition.',
            );
        }

        $this->requirePermission('pp:siem-manage');

        $this->_readOnly = !Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

        return true;
    }

    /**
     * Deletes a forwarder.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionDelete(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireAdminChanges();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('id');

        if (!PasswordPolicy::$plugin->getSiem()->deleteForwarder($id)) {
            return $this->asFailure(Craft::t('password-policy', 'Couldn’t delete forwarder.'));
        }

        return $this->asSuccess();
    }

    /**
     * Edit screen for an existing or new forwarder.
     *
     * @param int|null $forwarderId
     * @param SiemForwarderModel|null $forwarder injected by the URL manager from
     *     route params on a failed save, preserving in-flight edits
     * @return Response
     *
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionEdit(?int $forwarderId = null, ?SiemForwarderModel $forwarder = null): Response
    {
        if ($forwarder === null) {
            if ($forwarderId !== null) {
                $forwarder = PasswordPolicy::$plugin->getSiem()->getForwarderById($forwarderId);

                if ($forwarder === null) {
                    throw new NotFoundHttpException('Forwarder not found.');
                }
            } else {
                if ($this->_readOnly) {
                    throw new ForbiddenHttpException(
                        'Administrative changes are disallowed in this environment.',
                    );
                }

                $forwarder = new SiemForwarderModel();
            }
        }

        $isNew = $forwarder->id === null;

        $response = $this->asCpScreen()
            ->title($isNew
                ? Craft::t('password-policy', 'New SIEM forwarder')
                : ($forwarder->name ?: sprintf('%s:%d', $forwarder->host, $forwarder->port)))
            ->selectedSubnavItem('siem-forwarders')
            ->addCrumb(
                Craft::t('password-policy', 'Password Policy'),
                'password-policy',
            )
            ->addCrumb(
                Craft::t('password-policy', 'SIEM forwarders'),
                'password-policy/siem',
            )
            ->contentTemplate('password-policy/_siem/_edit', [
                'forwarder' => $forwarder,
                'isNew' => $isNew,
                'readOnly' => $this->_readOnly,
            ]);

        if (!$this->_readOnly) {
            $response
                ->action('password-policy/siem-forwarder/save')
                ->redirectUrl('password-policy/siem')
                ->saveShortcutRedirectUrl('password-policy/siem/{id}');
        }

        if ($this->_readOnly) {
            $response->noticeHtml(Cp::readOnlyNoticeHtml());
        }

        return $response;
    }

    /**
     * Index — list all forwarders.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $forwarders = PasswordPolicy::$plugin->getSiem()->listForwarders();

        return $this->renderTemplate('password-policy/_siem/_index', [
            'forwarders' => $forwarders,
            'readOnly' => $this->_readOnly,
        ]);
    }

    /**
     * Resets a forwarder's circuit-breaker state.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionResetCircuit(): Response
    {
        $this->requirePostRequest();
        $this->_requireAdminChanges();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('forwarderId');

        if (!PasswordPolicy::$plugin->getSiem()->resetCircuit($id)) {
            $this->setFailFlash(Craft::t('password-policy', 'Couldn’t reset circuit.'));
        } else {
            $this->setSuccessFlash(Craft::t('password-policy', 'Circuit reset.'));
        }

        return $this->redirectToPostedUrl();
    }

    /**
     * Saves a forwarder from POST.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();
        $this->_requireAdminChanges();

        $request = Craft::$app->getRequest();
        $forwarderId = $request->getBodyParam('forwarderId');

        $service = PasswordPolicy::$plugin->getSiem();

        if ($forwarderId !== null && $forwarderId !== '') {
            $forwarder = $service->getForwarderById((int)$forwarderId);

            if ($forwarder === null) {
                throw new BadRequestHttpException('Invalid or missing forwarder ID.');
            }
        } else {
            $forwarder = new SiemForwarderModel();
        }

        $forwarder->name = $request->getBodyParam('name') ?: null;
        $forwarder->protocol = (string)$request->getBodyParam('protocol', SiemForwarderModel::PROTOCOL_SYSLOG_TLS);
        $forwarder->host = (string)$request->getBodyParam('host', '');
        $forwarder->port = (int)$request->getBodyParam('port', SiemForwarderModel::DEFAULT_SYSLOG_TLS_PORT);
        $forwarder->tlsCertVerify = (bool)$request->getBodyParam('tlsCertVerify', true);
        $forwarder->tlsCaBundlePath = $request->getBodyParam('tlsCaBundlePath') ?: null;
        $forwarder->enabled = (bool)$request->getBodyParam('enabled', true);

        $eventClasses = $request->getBodyParam('eventClasses');
        $forwarder->eventClasses = $this->_normalizeEventClasses($eventClasses);

        if (!$service->saveForwarder($forwarder)) {
            return $this->asModelFailure(
                $forwarder,
                Craft::t('password-policy', 'Couldn’t save forwarder.'),
                'forwarder',
            );
        }

        return $this->asModelSuccess(
            $forwarder,
            Craft::t('password-policy', 'Forwarder saved.'),
            'forwarder',
        );
    }

    /**
     * Sends a synthetic test event through a forwarder. Returns JSON
     * with success/error message — the front-end surfaces via
     * `Craft.cp.displayNotice` / `displayError`.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSendTest(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireAdminChanges();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('forwarderId');
        $service = PasswordPolicy::$plugin->getSiem();
        $forwarder = $service->getForwarderById($id);

        if ($forwarder === null) {
            return $this->asFailure(Craft::t('password-policy', 'Forwarder not found.'));
        }

        try {
            $accepted = $service->sendTestEvent($forwarder);
        } catch (Throwable $e) {
            // Defense-in-depth: surface a generic message to the CP
            // admin and pin the actual exception to the plugin log.
            // Raw TLS connect errors carry internal hostnames, IPs and
            // port numbers that don't belong in a UI response — even a
            // privileged one. Forwarder-level details belong in the
            // operator's log channel.
            Craft::error(
                'SIEM test event failed: ' . $e->getMessage(),
                'password-policy',
            );

            return $this->asFailure(Craft::t(
                'password-policy',
                'Test event failed. Check the plugin log for details.',
            ));
        }

        return $accepted
            ? $this->asSuccess(Craft::t('password-policy', 'Test event delivered.'))
            : $this->asFailure(Craft::t(
                'password-policy',
                'Test event was logged but the forwarder refused or timed out.',
            ));
    }

    // Private Methods
    // =========================================================================

    /**
     * Normalizes the `eventClasses` POST shape — accepts both a JSON-
     * encoded string (textarea) and a plain array (multi-select). Empty
     * input becomes null so the model + service treat the forwarder as
     * "use the global setting."
     *
     * @param mixed $raw
     * @return array<int, string>|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _normalizeEventClasses(mixed $raw): ?array
    {
        if ($raw === null || $raw === '' || $raw === []) {
            return null;
        }

        if (is_string($raw)) {
            $decoded = json_decode($raw, true);

            if (is_array($decoded)) {
                $raw = $decoded;
            } else {
                // Fall back to comma-separated parsing.
                $raw = array_map('trim', explode(',', $raw));
            }
        }

        if (!is_array($raw)) {
            return null;
        }

        $cleaned = array_values(array_filter(
            array_map(fn($v) => is_string($v) ? trim($v) : '', $raw),
            fn($v) => $v !== '',
        ));

        return $cleaned !== [] ? $cleaned : null;
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
}
