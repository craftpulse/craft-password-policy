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
use craft\web\Controller;

use craft\web\View;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\BadRequestHttpException;
use yii\web\Response;

/**
 * Class RetentionController
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
*/
class RetentionController extends Controller
{
    /**
     * @inheritdoc
     */
    public $enableCsrfValidation = false;

    /**
     * @inheritdoc
     */
    protected array|bool|int $allowAnonymous = true;

    /**
     * @inheritdoc
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $request = Craft::$app->getRequest();

        // Require permission if posted from the CP
        if ($request->getIsPost() && $request->getIsCpRequest()) {
            $this->requirePermission('pp:' . $action->id);
        }

        return true;
    }

    /**
     * Forces the password resets.
     */
    public function actionForceResetPasswords(): ?Response
    {
        if (!PasswordPolicy::$plugin->settings->retentionUtilities) {
            return $this->getFailureResponse('Password retention features are disabled.');
        }

        PasswordPolicy::$plugin->retention->resetPasswords();

        return $this->getSuccessResponse('Users which will receive a password reset successfully queued.');
    }

    /**
     * @inheritdoc
     */
    public function afterAction($action, $result): mixed
    {
        // If front-end request, run the queue to ensure action is completed in full
        if (Craft::$app->getView()->templateMode == View::TEMPLATE_MODE_SITE) {
            Craft::$app->runAction('queue/run');
        }

        return parent::afterAction($action, $result);
    }

    /**
     * @param string $message
     * @return Response|null
     * @throws BadRequestHttpException
     * @throws Throwable
     */
    private function getSuccessResponse(string $message): ?Response
    {
        PasswordPolicy::$plugin->log($message . ' [via sync utility by "{username}"]');

        $this->setSuccessFlash(Craft::t('password-policy', $message));

        return $this->getResponse($message);
    }

    /**
     * @param string $message
     * @param bool $success
     * @return Response|null
     * @throws BadRequestHttpException
     */
    private function getResponse(string $message, bool $success = true): ?Response
    {
        $request = Craft::$app->getRequest();

        // If front-end or JSON request
        if (Craft::$app->getView()->templateMode == View::TEMPLATE_MODE_SITE || $request->getAcceptsJson()) {
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
