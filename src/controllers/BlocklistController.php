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
use craft\helpers\Queue;
use craft\helpers\UrlHelper;
use craft\web\Controller;

use craftpulse\passwordpolicy\base\RequiresEditionTrait;
use craftpulse\passwordpolicy\jobs\SeedBlocklist;
use craftpulse\passwordpolicy\PasswordPolicy;

use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class BlocklistController
 *
 * Handles CP actions for the password blocklist surface — the page rendered
 * at `password-policy/blocklist` plus the write actions behind it.
 *
 * Permission split:
 *  - `pp:blocklist-view`: required to access the controller at all
 *    (read the page, see counts, see the custom-words list).
 *  - `pp:blocklist-manage`: additionally required for write actions
 *    (`update-common`, `save-custom`).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BlocklistController extends Controller
{
    // Traits
    // =========================================================================

    use RequiresEditionTrait;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * The whole controller is Pro-only: every action either renders the
     * blocklist editor or backs one of its forms / AJAX calls, and the
     * subnav entry plus the `pp:blocklist-*` permissions only exist on Pro.
     * Below Pro the screen is hidden, so a direct hit 404s. Lite operators
     * seed the common list through the `password-policy/blocklist/update`
     * console command, which runs on every edition.
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException if the user lacks `pp:blocklist-view`
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
        $this->requirePermission('pp:blocklist-view');

        return true;
    }

    /**
     * Renders the Blocklist page — stats, "Update Common Passwords" button,
     * and the editable-table editor for custom words. Edition-gated to Pro.
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
        $blocklist = $plugin->getBlocklist();

        $pluginName = 'Password Policy';
        $templateTitle = Craft::t('password-policy', 'Blocklist');

        return $this->renderTemplate('password-policy/_blocklist/_index', [
            'pluginName' => $pluginName,
            'title' => $templateTitle,
            'docTitle' => "{$pluginName} - {$templateTitle}",
            'crumbs' => [
                [
                    'label' => $pluginName,
                    'url' => UrlHelper::cpUrl('password-policy'),
                ],
            ],
            'commonCount' => $blocklist->getCommonCount(),
            'customWords' => $blocklist->getAllCustomWords(),
            'lastUpdated' => $blocklist->getLastUpdated(),
        ]);
    }

    /**
     * Looks up a single word in the blocklist and returns a JSON yes/no
     * (with the matching source if any). Permission: `pp:blocklist-view`
     * inherited from `beforeAction`. The submitted word is not logged
     * anywhere — admins/auditors checking real passwords can use this
     * without leaving a trace in the plugin log.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionCheck(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();

        $word = (string)Craft::$app->getRequest()->getRequiredBodyParam('word');
        $result = PasswordPolicy::$plugin->getBlocklist()->isBlocked($word);

        return $this->asJson($result);
    }

    /**
     * Pushes a queue job to seed/refresh the common password blocklist
     * from the bundled data file. Production sysadmins run this after
     * a plugin upgrade that ships a new bundled list.
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
    public function actionUpdateCommon(): ?Response
    {
        $this->requirePostRequest();
        $this->requirePermission('pp:blocklist-manage');

        Queue::push(new SeedBlocklist());

        PasswordPolicy::$plugin->log('Common password blocklist update queued [by "{username}"]');

        $this->setSuccessFlash(
            Craft::t('password-policy', 'Common password blocklist update has been queued.'),
        );

        return $this->redirectToPostedUrl();
    }

    /**
     * Saves the custom blocklist from an EditableTable POST. The whole
     * table state is submitted as `words[<rowId>][word] = '<value>'` —
     * numeric `rowId` keys are existing rows the admin kept; non-numeric
     * keys (e.g. `new1`) are rows added in this edit. Unsubmitted existing
     * IDs are deletions.
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
    public function actionSaveCustom(): ?Response
    {
        $this->requirePostRequest();
        $this->requirePermission('pp:blocklist-manage');

        $rows = (array)Craft::$app->getRequest()->getBodyParam('words', []);
        $blocklist = PasswordPolicy::$plugin->getBlocklist();

        $existing = [];
        foreach ($blocklist->getAllCustomWords() as $r) {
            $existing[(int)$r['id']] = strtolower((string)$r['word']);
        }

        $keepIds = [];
        $newWords = [];

        foreach ($rows as $rowId => $row) {
            $word = strtolower(trim((string)($row['word'] ?? '')));
            if ($word === '') {
                continue;
            }

            // Numeric rowId + word matches the stored value → no-op, keep the row.
            // Anything else (new row, or existing row whose word changed) is
            // treated as an insert; the old ID falls out of $keepIds and gets
            // deleted in the diff below.
            if (is_numeric($rowId) && ($existing[(int)$rowId] ?? null) === $word) {
                $keepIds[] = (int)$rowId;
            } else {
                $newWords[] = $word;
            }
        }

        foreach (array_diff(array_keys($existing), $keepIds) as $idToRemove) {
            $blocklist->removeCustomWord($idToRemove);
        }

        foreach ($newWords as $word) {
            $blocklist->addCustomWord($word);
        }

        PasswordPolicy::$plugin->log('Custom blocklist updated [by "{username}"]');

        $this->setSuccessFlash(
            Craft::t('password-policy', 'Custom blocklist saved.'),
        );

        return $this->redirectToPostedUrl();
    }
}
