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
use craft\web\Controller;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

/**
 * Class ApiTokenController
 *
 * CP management for the Feature 2 REST API tokens (Enterprise). Issues +
 * revokes the Bearer tokens the read-only `ApiController` authenticates
 * against. Edition-gated to Enterprise on every action; permission-gated on
 * `pp:api-manage`.
 *
 * Three lines of defense (mirror SIEM / webhooks):
 *
 *  1. Subnav doesn't register on Lite / Pro
 *     ({@see PasswordPolicy::getCpNavItem()}).
 *  2. The permission only registers on Enterprise
 *     ({@see PasswordPolicy::_registerUserPermissions()}).
 *  3. This controller's `beforeAction()` rejects anyone who slipped past
 *     those (e.g. a bookmarked URL after an edition downgrade).
 *
 * Once-and-only-once plaintext surfacing
 * --------------------------------------
 * `actionIssue` mints the token through `ApiTokenService::issue()` (which
 * returns the plaintext exactly once), stashes the plaintext into the
 * session flash under `pp-api-token`, and redirects to the index. The next
 * index render consumes the flash and renders the plaintext in a
 * display-once panel with a copy-to-clipboard control; subsequent renders
 * show only the stored `tokenPrefix`. The plaintext is GONE from the
 * controller surface as soon as the response is built — it is never
 * persisted and never recoverable.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ApiTokenController extends Controller
{
    // Const Properties
    // =========================================================================

    /**
     * @var string session flash key carrying the freshly-minted plaintext
     *     token to the next index render. Consumed once.
     */
    public const FLASH_NEW_TOKEN = 'pp-api-token';

    // Private Properties
    // =========================================================================

    /**
     * @var bool whether admin changes are disallowed in this environment.
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
                'REST API token management requires the Enterprise edition.',
            );
        }

        $this->requirePermission('pp:api-manage');

        $this->_readOnly = !Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

        return true;
    }

    /**
     * Index — lists all tokens (prefix + name + last-used + expiry). When a
     * token was just issued, the plaintext rides in via the session flash
     * and is rendered once.
     *
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $tokens = PasswordPolicy::$plugin->getApiTokens()->getAllTokens();
        $newToken = Craft::$app->getSession()->getFlash(self::FLASH_NEW_TOKEN);

        return $this->renderTemplate('password-policy/_api/_index', [
            'tokens' => $tokens,
            'newToken' => is_string($newToken) ? $newToken : null,
            'readOnly' => $this->_readOnly,
        ]);
    }

    /**
     * Issues a new token from POST. Surfaces the plaintext once via the
     * session flash, then redirects to the index.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIssue(): ?Response
    {
        $this->requirePostRequest();
        $this->_requireAdminChanges();

        $request = Craft::$app->getRequest();
        $name = trim((string)$request->getBodyParam('name', ''));

        if ($name === '') {
            $this->setFailFlash(Craft::t('password-policy', 'A token name is required.'));

            return $this->redirectToPostedUrl();
        }

        $expiresInDays = (int)$request->getBodyParam('expiresInDays', 0);
        $expiresAt = $expiresInDays > 0
            ? Carbon::now('UTC')->addDays($expiresInDays)->toDateTime()
            : null;

        $result = PasswordPolicy::$plugin->getApiTokens()->issue($name, null, $expiresAt);

        // Surface the plaintext exactly once — the next index render
        // consumes this flash and then it's gone.
        $this->flashNewToken($result['token']);
        $this->setSuccessFlash(Craft::t('password-policy', 'Token issued.'));

        return $this->redirect('password-policy/api-tokens');
    }

    /**
     * Revokes (deletes) a token by id.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionRevoke(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();
        $this->_requireAdminChanges();

        $id = (int)Craft::$app->getRequest()->getRequiredBodyParam('id');

        if (!PasswordPolicy::$plugin->getApiTokens()->revoke($id)) {
            return $this->asFailure(Craft::t('password-policy', 'Couldn’t revoke token.'));
        }

        return $this->asSuccess(Craft::t('password-policy', 'Token revoked.'));
    }

    // Protected Methods
    // =========================================================================

    /**
     * Stashes the freshly-minted plaintext token into the session flash so
     * the next index render can surface it once. Extracted as a seam so
     * console-bootstrapped tests (which have no session) can override it to
     * capture the plaintext without standing up session storage.
     *
     * @param string $plaintext
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function flashNewToken(#[\SensitiveParameter] string $plaintext): void
    {
        Craft::$app->getSession()->setFlash(self::FLASH_NEW_TOKEN, $plaintext);
    }

    // Private Methods
    // =========================================================================

    /**
     * Guards write actions when `allowAdminChanges` is off.
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
