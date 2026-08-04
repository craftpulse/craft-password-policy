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
use craft\helpers\Cp;
use craft\web\Controller;
use craftpulse\passwordpolicy\base\RequiresEditionTrait;
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
    // Traits
    // =========================================================================

    use RequiresEditionTrait;

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
     * @throws ForbiddenHttpException if the user lacks the required permission
     * @throws NotFoundHttpException if the edition is below Enterprise
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
        $this->requireEnterpriseEdition();

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
                : $forwarder->getDisplayName())
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
     * Also carries the sweep-health verdict for the cron warning. The
     * `password-policy/siem/run` sweep is operator-scheduled, and an
     * install that never wired it up looks identical to a healthy one from
     * this screen: an enabled forwarder, a closed circuit, and no
     * deliveries. {@see \craftpulse\passwordpolicy\services\ComplianceAggregateService::getSiemSweepHealth()}
     * turns that silence into something the operator can see.
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
            'sweepHealth' => PasswordPolicy::$plugin->getComplianceAggregates()->getSiemSweepHealth(),
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
        $forwarder->host = $request->getBodyParam('host') ?: null;
        $port = $request->getBodyParam('port');
        $forwarder->port = ($port === null || $port === '') ? null : (int)$port;
        $forwarder->url = $request->getBodyParam('url') ?: null;
        $forwarder->authType = (string)$request->getBodyParam('authType', SiemForwarderModel::AUTH_TYPE_NONE);
        $forwarder->framing = (string)$request->getBodyParam(
            'framing',
            SiemForwarderModel::FRAMING_OCTET_COUNTED,
        );
        $forwarder->headers = $this->_normalizeHeaders($request->getBodyParam('headers'));
        $forwarder->tlsCertVerify = (bool)$request->getBodyParam('tlsCertVerify', true);
        $forwarder->tlsCaBundlePath = $request->getBodyParam('tlsCaBundlePath') ?: null;
        $forwarder->enabled = (bool)$request->getBodyParam('enabled', true);

        // The credential is never rendered back into the form, so an empty
        // POST means "keep what's stored" rather than "clear it". The model
        // it was hydrated from already carries the decrypted value; a fresh
        // model carries null and validation refuses that when the auth type
        // needs one. Clearing a stored token is done by switching the auth
        // type to `none`, which `toRecordAttributes()` acts on.
        $submittedToken = $request->getBodyParam('authToken');

        if (is_string($submittedToken) && $submittedToken !== '') {
            $forwarder->authToken = $submittedToken;
        }

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
     * Normalizes the editable table's `headers` POST shape into the
     * name => value map the model validates and the record stores.
     *
     * The table posts a list of rows, each `['name' => …, 'value' => …]`.
     * Rows with an empty name are dropped: an operator who clicks "Add a
     * header" and then saves without filling it in means nothing by it.
     * Names and values are trimmed; a name that survives with an empty
     * value reaches the model's validator, which rejects it, rather than
     * being silently dropped.
     *
     * @param mixed $raw
     * @return array<string, string>|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _normalizeHeaders(mixed $raw): ?array
    {
        if (!is_array($raw)) {
            return null;
        }

        $headers = [];

        foreach ($raw as $row) {
            if (!is_array($row)) {
                continue;
            }

            $name = is_string($row['name'] ?? null) ? trim($row['name']) : '';

            if ($name === '') {
                continue;
            }

            $headers[$name] = is_string($row['value'] ?? null) ? trim($row['value']) : '';
        }

        return $headers !== [] ? $headers : null;
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
