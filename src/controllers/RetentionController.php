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
use craft\web\Controller;

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\RetentionService;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

/**
 * Class RetentionController
 *
 * POST target for the "Force Reset Passwords" action on the Password
 * Retention utility. Mass path only: it flags every account a retention
 * sweep already found past the configured expiry window, and there is no
 * way to point it at a named user.
 *
 * No edition gate, deliberately. The mass path is universal on every
 * edition. It shipped in 5.1.2, before the plugin had editions, so every
 * install that updates into 5.2.0 already has it and every one of them
 * resolves to Lite by default; gating it would withdraw a capability
 * those installs already paid for. The Pro capability is the additive
 * per-user one, which lives on
 * {@see \craftpulse\passwordpolicy\controllers\UserSecurityController}
 * and is gated there.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 *
 * @property RetentionService $retention
 */
class RetentionController extends Controller
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();
        $this->requirePostRequest();
        $this->requirePermission(PasswordPolicy::PERMISSION_FORCE_RESET_PASSWORDS);

        return true;
    }

    /**
     * Forces a password reset on every already-expired account. Queued,
     * so a large user table doesn't block the request.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     */
    public function actionForceResetPasswords(): ?Response
    {
        if (!PasswordPolicy::$plugin->getSettings()->retentionUtilities) {
            return $this->_getFailureResponse('Password retention features are disabled.');
        }

        PasswordPolicy::$plugin->retention->resetPasswords();

        return $this->_getSuccessResponse('Users which will receive a password reset successfully queued.');
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns a success response.
     *
     * @param string $message
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     */
    private function _getSuccessResponse(string $message): ?Response
    {
        PasswordPolicy::$plugin->log($message . ' [via sync utility by "{username}"]');

        $this->setSuccessFlash(Craft::t('password-policy', $message));

        return $this->_getResponse($message);
    }

    /**
     * Returns a failure response.
     *
     * @param string $message
     * @return Response|null
     *
     * @throws BadRequestHttpException
     *
     * @author CraftPulse
     */
    private function _getFailureResponse(string $message): ?Response
    {
        $this->setFailFlash(Craft::t('password-policy', $message));

        return $this->_getResponse($message, false);
    }

    /**
     * Returns a JSON or redirect response.
     *
     * @param string $message
     * @param bool $success
     * @return Response|null
     *
     * @throws BadRequestHttpException
     *
     * @author CraftPulse
     */
    private function _getResponse(string $message, bool $success = true): ?Response
    {
        $request = Craft::$app->getRequest();

        if ($request->getAcceptsJson()) {
            return $this->asJson([
                'success' => $success,
                'message' => Craft::t('password-policy', $message),
            ]);
        }

        if (!$success) {
            return null;
        }

        return $this->redirectToPostedUrl();
    }
}
