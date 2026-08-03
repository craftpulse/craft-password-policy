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
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\web\Controller;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\models\AuditContext;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\SecurityService;
use Throwable;
use yii\base\InvalidConfigException;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class UserPasswordController
 *
 * CP POST target for the two D3 element actions on the Users index:
 *
 *  - `actionChange()` — handles the `ChangeUserPassword` modal submit.
 *    Admin-direct password change with elevated session, per-policy
 *    validation, explicit `AuditContext::adminChange()` propagated to
 *    the central history-write listener via
 *    `UserStateService::setExplicitContext()`. Also clears any prior
 *    pending reason on the user (admin direct intent overrides
 *    breach/expiry/etc. flags).
 *
 *  - `actionSendResetEmail()` — confirm-dialog endpoint that mirrors
 *    the `SendPasswordResetEmail` element action's `performAction()`
 *    for ergonomic single-user sends from the user-edit tab. The
 *    bulk path stays in the action class.
 *
 * Both actions: CP POST only, `pp:change-user-passwords` permission,
 * elevated session required (defense-in-depth — `$user->newPassword`
 * is a sensitive operation regardless of the surface that triggered
 * it). `actionChange()` rejects bulk POSTs (`userId[]`) per the
 * single-user-only contract, and refuses a non-admin actor aiming at
 * an admin target via {@see SecurityService::canManageUserCredentials()}.
 *
 * `actionSendResetEmail()` carries no peer-admin guard, deliberately.
 * It mails a reset link to the target's own address rather than
 * replacing their credential, so it crosses no privilege boundary,
 * and Craft core lets any holder of `editUsers` send one to an admin
 * (`UsersController::actionSendPasswordResetEmail()`).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserPasswordController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int|string>|bool|int CP-only — both endpoints require an
     *     authenticated admin session.
     */
    protected array|bool|int $allowAnonymous = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Pre-action gates shared by every endpoint on this controller:
     * CP request, POST method, permission, elevated session. The
     * elevated-session requirement applies to both actions on purpose
     * — sending a reset email is the start of a credential-replacement
     * flow and deserves the same friction as setting a password
     * directly.
     *
     * @param \yii\base\Action $action
     * @return bool
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
        $this->requirePermission('pp:change-user-passwords');
        $this->requireElevatedSession();

        return true;
    }

    /**
     * Sets a target user's password directly. Counterpart to the
     * `ChangeUserPassword` element action's modal submission.
     *
     * Behavior:
     *  - 400 on bulk POST (`userId[]`) — the action is single-user-only.
     *  - 400 if `newPassword` and `newPasswordConfirm` don't match.
     *  - 400 if the target user is the current user — admins self-
     *    service their own password through Craft's standard account
     *    screen, not this admin-on-user surface.
     *  - 403 if `allowAdminChanges = false`.
     *  - 403 if a non-admin aims this at an admin
     *    ({@see SecurityService::canManageUserCredentials()}) — setting an
     *    administrator's password outright is account takeover, and
     *    `pp:change-user-passwords` is grantable to any group.
     *  - 404 if the target user doesn't exist.
     *  - Re-renders with errors when the new password fails policy
     *    validation (`User::EVENT_DEFINE_RULES`).
     *
     * On success: pins an explicit `AuditContext::adminChange()` so
     * the central history-write listener records `changeReason =
     * admin_change` + `changedByUserId = <currentAdminId>`. Then either
     * clears the prior pending reason (admin direct intent overrides
     * breach/expiry/etc.) OR — when this is an initial-password setup
     * under the force-change policy — re-pins `FirstLoginForced` so the
     * user's eventual forced reset is captured accurately.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     * @throws InvalidConfigException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionChange(): ?Response
    {
        if (!Craft::$app->getConfig()->getGeneral()->allowAdminChanges) {
            throw new ForbiddenHttpException('Administrative changes are disallowed in this environment.');
        }

        $request = Craft::$app->getRequest();
        $userIdRaw = $request->getRequiredBodyParam('userId');

        // Bulk POSTs (`userId[]`) are explicitly rejected — the modal is
        // single-user-only by design (security: setting the same
        // password on N users is a one-leak-fells-many anti-pattern).
        // Defense-in-depth: the action's `validateSelection` already
        // rejects multi-selection in the JS layer; the controller
        // rejects again here so a hand-crafted curl can't bypass.
        if (is_array($userIdRaw)) {
            throw new BadRequestHttpException('Change password is a single-user action.');
        }

        $userId = (int)$userIdRaw;
        $user = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null) {
            throw new NotFoundHttpException('User not found.');
        }

        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser !== null && $currentUser->id === $user->id) {
            throw new BadRequestHttpException(
                'Use the standard account password screen to change your own password.',
            );
        }

        // Peer-admin guard, before anything reads the submitted password.
        // `pp:change-user-passwords` is grantable to any group, and setting an
        // account's password outright is takeover of that account, so the
        // permission cannot be allowed to carry "become an administrator" with
        // it. The elevated-session requirement is no obstacle here either: the
        // attacker re-enters their OWN password to elevate.
        //
        // Re-checked in the controller rather than only where the action menu
        // renders, because the target id arrives in the POST body and can name a
        // user no rendered screen ever offered.
        if (!PasswordPolicy::$plugin->getSecurity()->canManageUserCredentials($user, $currentUser)) {
            throw new ForbiddenHttpException(
                Craft::t('password-policy', 'Only an admin can change another admin’s password.'),
            );
        }

        $newPassword = (string)$request->getRequiredBodyParam('newPassword');
        $confirm = (string)$request->getRequiredBodyParam('newPasswordConfirm');

        if ($newPassword === '') {
            return $this->_failure($user, ['newPassword' => Craft::t('app', 'Password is required.')]);
        }

        if ($newPassword !== $confirm) {
            return $this->_failure($user, [
                'newPasswordConfirm' => Craft::t('app', 'Passwords don’t match.'),
            ]);
        }

        // Pin the explicit context BEFORE saveElement fires the
        // EVENT_AFTER_SAVE listener. The listener consumes the slot
        // (single-use) and writes the history row with
        // `changeReason = admin_change` + the acting admin's id.
        $context = AuditContext::adminChange((int)$currentUser?->id);

        $userState = PasswordPolicy::$plugin->getUserState();
        $userState->setExplicitContext($user, $context);

        // Capture pre-save state for the force-change-on-first-login
        // policy preservation below. Read directly from the users table
        // — `UserQuery::beforePrepare()` doesn't `addSelect()` the
        // `passwordResetRequired` column (Craft 5.x), so the in-memory
        // `$user->passwordResetRequired` is always false on a freshly-
        // loaded User regardless of DB state. The plugin already takes
        // the same direct-query path for `lastPasswordChangeDate` in
        // `UserSecurityController::actionEditTab()`; mirror it here.
        //
        // `lastLoginDate` IS selected by `UserQuery::beforePrepare()`,
        // so `$user->lastLoginDate` is reliable. Read it from the
        // element. The settings model also reads from the live plugin
        // singleton, so no DB hit needed for `forceChangeOnFirstLogin`.
        $settings = PasswordPolicy::$plugin->getSettings();
        $preSaveFlag = (bool)(new Query())
            ->select(['passwordResetRequired'])
            ->from(Table::USERS)
            ->where(['id' => $user->id])
            ->scalar();
        $shouldPreserveForceReset = (
            $settings->forceChangeOnFirstLogin
            && $user->lastLoginDate === null
            && $preSaveFlag
        );

        $user->newPassword = $newPassword;

        if (!Craft::$app->getElements()->saveElement($user)) {
            // Save failed — drop the explicit-context slot we pinned so
            // a follow-up unrelated save doesn't pick up a stale
            // context. `consumeExplicitContext()` is the only public
            // clear path; calling it here drains the slot.
            $userState->consumeExplicitContext($user);

            return $this->_failure($user, $user->getErrors());
        }

        // Force-change-on-first-login policy preservation. Craft's
        // `User::afterSave` cleared the flag for us (because newPassword
        // was set on a non-new user that previously had the flag — see
        // `vendor/craftcms/cms/src/elements/User.php` line 2632), which
        // is Craft's standard semantic: "user just changed their
        // password, no further reset needed." For ordinary admin
        // password changes (target user has logged in before), that's
        // the right answer; we leave the clear in place.
        //
        // For the initial-password-setup flow — target user has NEVER
        // logged in AND the global `forceChangeOnFirstLogin` policy is
        // active AND the flag was set pre-save (typically by the
        // plugin's own user-creation listener) — the modal is being
        // used to set a *temporary* admin-assigned password, and the
        // policy promises the user must reset it on first login. Re-
        // assert the flag with a non-newPassword save so Craft's clear
        // logic doesn't re-fire and silently undo the policy's promise.
        //
        // Confirmed during the 2026-05-22 Phase H smoke walk (S1.6).
        if ($shouldPreserveForceReset) {
            $user->passwordResetRequired = true;

            // Check the re-save result. If it fails, the force-reset
            // guarantee is silently dropped while `setPendingReason()`
            // still records the intent — leaving the user able to keep a
            // breach/temporary password past first login. Log loud so the
            // dropped guarantee is visible; still record the pending
            // reason so audit capture stays accurate for any reset that
            // does eventually occur.
            if (!Craft::$app->getElements()->saveElement($user, false)) {
                Craft::error(
                    'Failed to re-assert passwordResetRequired on user ' . $user->id .
                    ' after admin password change (force-change-on-first-login preservation): ' .
                    implode('; ', $user->getFirstErrors()),
                    'password-policy',
                );
            }

            // The user still owes a forced first-login reset. The admin-
            // change save above already consumed the FirstLoginForced
            // pending reason via the central listener's post-change
            // `clearPendingReason()` (PasswordPolicy.php). Re-pin it so the
            // user's eventual forced reset records `changeReason =
            // first_login_forced` on its history row, not the request-
            // derived `self_service` fallback. Audit capture must stay
            // accurate (memory: project_audit_capture_principle.md).
            $userState->setPendingReason($user, ChangeReason::FirstLoginForced);
        } else {
            // Admin direct intent overrides any prior pending reason
            // (breach, expiry, first-login, admin-force-reset). Clear so
            // the audit trail reflects the new intent and no stale flag
            // dangles.
            $userState->clearPendingReason($user);
        }

        return $this->_success(
            $user,
            Craft::t('password-policy', 'Password updated for {user}.', [
                'user' => (string)($user->getFullName() ?: $user->username ?: $user->email),
            ]),
        );
    }

    /**
     * Sends a password reset email to a single user. Mirror of the
     * `SendPasswordResetEmail` element action's `performAction()` for
     * the single-user surface (e.g. user-edit tab).
     *
     * Behavior:
     *  - 403 if `allowAdminChanges = false`.
     *  - 404 if the target user doesn't exist.
     *  - 400 if `Users::sendPasswordResetEmail()` returns false.
     *
     * On success: pins an `AdminForceReset` pending reason so the
     * user's NEXT password change records the right cause.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     * @throws InvalidConfigException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSendResetEmail(): ?Response
    {
        if (!Craft::$app->getConfig()->getGeneral()->allowAdminChanges) {
            throw new ForbiddenHttpException('Administrative changes are disallowed in this environment.');
        }

        $userId = (int)Craft::$app->getRequest()->getRequiredBodyParam('userId');
        $user = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null) {
            throw new NotFoundHttpException('User not found.');
        }

        // Pin pending reason BEFORE the email send so user_state
        // reflects intent even if SMTP fails downstream. The listener
        // consumes the reason on the user's next change; a never-
        // completed change just leaves a harmless pending row.
        PasswordPolicy::$plugin->getUserState()->setPendingReason(
            $user,
            ChangeReason::AdminForceReset,
        );

        if (!Craft::$app->getUsers()->sendPasswordResetEmail($user)) {
            return $this->_failure(
                $user,
                ['email' => Craft::t('password-policy', 'Could not send password reset email.')],
            );
        }

        return $this->_success(
            $user,
            Craft::t('password-policy', 'Password reset email sent to {email}.', [
                'email' => (string)$user->email,
            ]),
        );
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns a failure response. JSON for AJAX callers (the modal +
     * the user-edit tab); a flash + posted-URL redirect for plain
     * form posts.
     *
     * Inlined rather than delegated to `asModelFailure()` because the
     * latter pulls in `Cp::chipHtml($user)` for notification settings,
     * which builds CP URLs and needs a request-host context that the
     * test stub doesn't have. The endpoints here only need to surface
     * `errors` + `message` to the modal — `asModelFailure`'s extra
     * payload (`modelName`, `user.toArray()`) isn't consumed.
     *
     * @param User $user the target user (kept on the signature for
     *     future use; today we expose the per-field errors only)
     * @param array<string, mixed> $errors per-field error messages
     * @return Response|null
     *
     * @throws BadRequestHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _failure(User $user, array $errors): ?Response
    {
        $message = Craft::t('password-policy', 'Couldn’t update password.');

        if ($this->request->getAcceptsJson()) {
            $this->response->setStatusCode(400);
            return $this->asJson([
                'message' => $message,
                'errors' => $errors,
            ]);
        }

        $this->setFailFlash($message);
        Craft::$app->getSession()->setFlash('errors', $errors);

        return null;
    }

    /**
     * Returns a success response. Same JSON-vs-redirect split as
     * `_failure()`; same rationale for inlining over `asModelSuccess()`
     * — the chip-HTML notification settings would build CP URLs and
     * the test stub doesn't carry a host context.
     *
     * @param User $user the target user (signature reserved for
     *     future per-user metadata; today we surface message only)
     * @param string $message the success message
     * @return Response
     *
     * @throws BadRequestHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _success(User $user, string $message): Response
    {
        if ($this->request->getAcceptsJson()) {
            return $this->asJson([
                'success' => true,
                'message' => $message,
            ]);
        }

        $this->setSuccessFlash($message);

        return $this->redirectToPostedUrl();
    }
}
