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

use Carbon\Carbon;
use Craft;
use craft\helpers\Cp;
use craft\helpers\Queue;
use craft\web\Controller;
use craftpulse\passwordpolicy\base\RequiresEditionTrait;
use craftpulse\passwordpolicy\jobs\RotateWebhookSecretJob;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class WebhookEndpointController
 *
 * CP CRUD for the webhook endpoints surface (G9). Edition-gated to
 * Enterprise on every action; permission-gated on `pp:webhooks-manage`.
 *
 * Three lines of defense (mirror G8):
 *
 *  1. Subnav doesn't register on Lite / Pro
 *     ({@see PasswordPolicy::getCpNavItem()}).
 *  2. Permission only registers on Enterprise
 *     ({@see PasswordPolicy::_registerUserPermissions()}).
 *  3. This controller's `beforeAction()` rejects anyone who slipped
 *     past those (e.g. a bookmarked URL after an edition downgrade).
 *
 * Once-and-only-once secret surfacing
 * -----------------------------------
 * The plaintext secret crosses the controller surface in two paths:
 *
 *  - **On create**: `actionSave` populates the new endpoint via
 *    `WebhookService::saveEndpoint()` (which generates the initial
 *    secret), then captures the plaintext into the session flash
 *    under the `pp-webhook-secret` key. The next render of the edit
 *    page consumes the flash and renders the secret in a display-once
 *    panel; subsequent renders show no secret.
 *  - **On rotate**: `actionRotateSecret` returns the new plaintext as
 *    JSON (`{newSecret, graceWindowEndsAt}`); the front-end renders
 *    it inline with a copy-to-clipboard button. Closing the modal
 *    discards it.
 *
 * The plaintext is GONE from the controller surface as soon as the
 * response is built. Edit-form re-renders never include the secret.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookEndpointController extends Controller
{
    // Traits
    // =========================================================================

    use RequiresEditionTrait;

    // Const Properties
    // =========================================================================

    /**
     * Session flash key used to surface the plaintext secret of a
     * just-created endpoint to the next page render. Stored only for
     * the immediate redirect; never persisted.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const FLASH_KEY_NEW_SECRET = 'pp-webhook-new-secret';

    /**
     * Session flash key used to carry the endpoint ID that owns the
     * just-flashed secret. Used by the edit template to verify the
     * flash belongs to the endpoint being rendered.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const FLASH_KEY_NEW_SECRET_ENDPOINT_ID = 'pp-webhook-new-secret-endpoint-id';

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

        $this->requirePermission('pp:webhooks-manage');

        $this->_readOnly = !Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

        return true;
    }

    /**
     * Deletes an endpoint.
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

        if (!PasswordPolicy::$plugin->getWebhook()->deleteEndpoint($id)) {
            return $this->asFailure(Craft::t('password-policy', 'Couldn’t delete endpoint.'));
        }

        return $this->asSuccess();
    }

    /**
     * Edit screen for an existing or new endpoint.
     *
     * @param int|null $endpointId
     * @param WebhookEndpointModel|null $endpoint injected by the URL
     *     manager from route params on a failed save, preserving in-
     *     flight edits
     * @return Response
     *
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionEdit(?int $endpointId = null, ?WebhookEndpointModel $endpoint = null): Response
    {
        if ($endpoint === null) {
            if ($endpointId !== null) {
                $endpoint = PasswordPolicy::$plugin->getWebhook()->getEndpointById($endpointId);

                if ($endpoint === null) {
                    throw new NotFoundHttpException('Endpoint not found.');
                }
            } else {
                if ($this->_readOnly) {
                    throw new ForbiddenHttpException(
                        'Administrative changes are disallowed in this environment.',
                    );
                }

                $endpoint = new WebhookEndpointModel();
            }
        }

        $isNew = $endpoint->id === null;

        // Consume the once-and-only-once new-secret flash. Only render
        // when the flash matches the endpoint being viewed — a flash
        // pointing at a different endpoint (e.g. operator created
        // endpoint A, navigated to edit B) is silently dropped. Same
        // try/catch as `actionSave` — session may not be available
        // in non-CP contexts (tests, queue replays).
        $flashedSecret = null;
        try {
            $session = Craft::$app->getSession();
            $flashedEndpointId = $session->getFlash(self::FLASH_KEY_NEW_SECRET_ENDPOINT_ID);
            if ($flashedEndpointId !== null && (int)$flashedEndpointId === (int)$endpoint->id) {
                $flashedSecret = $session->getFlash(self::FLASH_KEY_NEW_SECRET);
            }
        } catch (Throwable) {
            // Session unavailable — render without the flash panel.
        }

        $response = $this->asCpScreen()
            ->title($isNew
                ? Craft::t('password-policy', 'New webhook endpoint')
                : ($endpoint->name ?: $endpoint->url))
            ->selectedSubnavItem('webhooks')
            ->addCrumb(
                Craft::t('password-policy', 'Password Policy'),
                'password-policy',
            )
            ->addCrumb(
                Craft::t('password-policy', 'Webhooks'),
                'password-policy/webhooks',
            )
            ->contentTemplate('password-policy/_webhooks/_edit', [
                'endpoint' => $endpoint,
                'isNew' => $isNew,
                'readOnly' => $this->_readOnly,
                'flashedSecret' => is_string($flashedSecret) ? $flashedSecret : null,
            ]);

        if (!$this->_readOnly) {
            $response
                ->action('password-policy/webhook-endpoint/save')
                ->redirectUrl('password-policy/webhooks')
                ->saveShortcutRedirectUrl('password-policy/webhooks/{id}');
        }

        if ($this->_readOnly) {
            $response->noticeHtml(Cp::readOnlyNoticeHtml());
        }

        return $response;
    }

    /**
     * Index — list all endpoints.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $endpoints = PasswordPolicy::$plugin->getWebhook()->listEndpoints();

        return $this->renderTemplate('password-policy/_webhooks/_index', [
            'endpoints' => $endpoints,
            'readOnly' => $this->_readOnly,
        ]);
    }

    /**
     * Resets an endpoint's circuit-breaker state.
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

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('endpointId');

        if (!PasswordPolicy::$plugin->getWebhook()->resetCircuit($id)) {
            $this->setFailFlash(Craft::t('password-policy', 'Couldn’t reset circuit.'));
        } else {
            $this->setSuccessFlash(Craft::t('password-policy', 'Circuit reset.'));
        }

        return $this->redirectToPostedUrl();
    }

    /**
     * Rotates an endpoint's HMAC secret. Returns the new plaintext as
     * JSON for one-time display in the front-end.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionRotateSecret(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireAdminChanges();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('endpointId');
        $service = PasswordPolicy::$plugin->getWebhook();
        $endpoint = $service->getEndpointById($id);

        if ($endpoint === null) {
            return $this->asFailure(Craft::t('password-policy', 'Endpoint not found.'));
        }

        try {
            $newSecret = $service->rotateSecret($endpoint);
        } catch (Throwable $e) {
            // Defense-in-depth: don't surface the raw exception to the
            // CP admin. `WebhookService::rotateSecret()` throws on model
            // validation failure; the message can embed DB field names,
            // model internals, or transitive details that don't belong
            // in a UI response. Mirror `actionTestFire()` — log the
            // exception via the plugin channel, return a generic
            // breadcrumb pointing the operator at the log.
            Craft::error(
                'Webhook secret rotation failed: ' . $e->getMessage(),
                'password-policy',
            );

            return $this->asFailure(Craft::t(
                'password-policy',
                "Couldn't rotate secret. Check the plugin log for details.",
            ));
        }

        // Schedule the previous-secret reaper to run after the
        // configured grace window. The job is idempotent — concurrent
        // rotations don't break it (each enqueues its own reaper; the
        // older one no-ops against the newer rotation timestamp).
        $graceHours = PasswordPolicy::$plugin->getSettings()->webhookSecretGracePeriodHours;
        $graceSeconds = max(1, $graceHours) * 3600;

        Queue::push(
            new RotateWebhookSecretJob(['endpointId' => (int)$endpoint->id]),
            null,
            $graceSeconds,
        );

        $graceEndsAt = Carbon::now('UTC')->addSeconds($graceSeconds);

        return $this->asJson([
            'success' => true,
            'newSecret' => $newSecret,
            'graceWindowEndsAt' => Craft::$app->getFormatter()->asDatetime(
                $graceEndsAt->toDateTime(),
                'short',
            ),
            'message' => Craft::t('password-policy', 'Secret rotated.'),
        ]);
    }

    /**
     * Saves an endpoint from POST. Generates the initial secret on
     * create and surfaces it via session flash for the next render.
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
        $endpointId = $request->getBodyParam('endpointId');

        $service = PasswordPolicy::$plugin->getWebhook();

        if ($endpointId !== null && $endpointId !== '') {
            $endpoint = $service->getEndpointById((int)$endpointId);

            if ($endpoint === null) {
                throw new BadRequestHttpException('Invalid or missing endpoint ID.');
            }

            $isNew = false;
        } else {
            $endpoint = new WebhookEndpointModel();
            $isNew = true;
        }

        $endpoint->name = $request->getBodyParam('name') ?: null;
        $endpoint->url = (string)$request->getBodyParam('url', '');
        $endpoint->enabled = (bool)$request->getBodyParam('enabled', true);

        $eventClasses = $request->getBodyParam('eventClasses');
        $endpoint->eventClasses = $this->_normalizeEventClasses($eventClasses);

        if (!$service->saveEndpoint($endpoint)) {
            return $this->asModelFailure(
                $endpoint,
                Craft::t('password-policy', 'Couldn’t save endpoint.'),
                'endpoint',
            );
        }

        // Surface the freshly-generated secret EXACTLY ONCE on create
        // via the flash session — the edit template reads it on the
        // next render. `WebhookEndpointModel::fields()` strips the
        // plaintext secrets from `asModelSuccess`, so the JSON
        // response does NOT carry the secret.
        if ($isNew && $endpoint->secretCurrent !== null) {
            try {
                $session = Craft::$app->getSession();
                $session->setFlash(self::FLASH_KEY_NEW_SECRET, $endpoint->secretCurrent);
                $session->setFlash(self::FLASH_KEY_NEW_SECRET_ENDPOINT_ID, (string)$endpoint->id);
            } catch (Throwable) {
                // Session unavailable (console / queue worker
                // context). The caller can read `$endpoint
                // ->secretCurrent` directly from the model returned by
                // `$service->saveEndpoint()`.
            }
        }

        return $this->asModelSuccess(
            $endpoint,
            Craft::t('password-policy', 'Endpoint saved.'),
            'endpoint',
        );
    }

    /**
     * Sends a synthetic test event through an endpoint. Returns JSON
     * with status code + duration + truncated body for inline display.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionTestFire(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireAdminChanges();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('endpointId');
        $service = PasswordPolicy::$plugin->getWebhook();
        $endpoint = $service->getEndpointById($id);

        if ($endpoint === null) {
            return $this->asFailure(Craft::t('password-policy', 'Endpoint not found.'));
        }

        try {
            $result = $service->sendTestEvent($endpoint);
        } catch (Throwable $e) {
            // Defense-in-depth: surface a generic message to the CP
            // admin and pin the actual exception to the plugin log.
            // Endpoint TLS / DNS errors carry internal hostnames + IPs
            // that don't belong in a UI response — even a privileged
            // one. Endpoint-level details belong in the operator's
            // log channel.
            Craft::error(
                'Webhook test fire failed: ' . $e->getMessage(),
                'password-policy',
            );

            return $this->asFailure(Craft::t(
                'password-policy',
                'Test event failed. Check the plugin log for details.',
            ));
        }

        return $this->asJson([
            'success' => $result['success'],
            'statusCode' => $result['statusCode'],
            'duration' => $result['duration'],
            'body' => $result['body'],
            'message' => $result['success']
                ? Craft::t('password-policy', 'Test event delivered ({code}).', ['code' => $result['statusCode']])
                : Craft::t(
                    'password-policy',
                    'Test event was logged but delivery failed.',
                ),
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Normalizes the `eventClasses` POST shape — accepts both a JSON-
     * encoded string and a plain array. Empty input becomes null so
     * the model + service treat the endpoint as "use the global
     * setting."
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
