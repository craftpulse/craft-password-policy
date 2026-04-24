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
use craft\helpers\Queue;
use craft\web\Controller;

use craftpulse\passwordpolicy\jobs\SeedBlocklist;
use craftpulse\passwordpolicy\PasswordPolicy;

use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

/**
 * Class BlocklistController
 *
 * Handles CP utility actions for the password blocklist.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BlocklistController extends Controller
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
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();
        $this->requirePostRequest();
        $this->requirePermission('pp:blocklist-manage');

        return true;
    }

    /**
     * Pushes a queue job to seed/refresh the common password blocklist
     * from the bundled data file.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionUpdateCommon(): ?Response
    {
        Queue::push(new SeedBlocklist());

        PasswordPolicy::$plugin->log('Common password blocklist update queued [via utility by "{username}"]');

        $this->setSuccessFlash(
            Craft::t('password-policy', 'Common password blocklist update has been queued.'),
        );

        return $this->redirectToPostedUrl();
    }
}
