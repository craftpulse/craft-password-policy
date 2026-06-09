<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers\front;

use Craft;
use craft\elements\User;
use craft\web\Controller;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\InvalidArgumentException;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

/**
 * Class PasswordChangeController
 *
 * Front-end POST target for the `passwordChangeForm()` Twig builder.
 * Allows a logged-in user to change their own password from a consumer
 * site form. Validates the current password, validates the new password
 * against the resolved policy via `User::EVENT_DEFINE_RULES`, and saves.
 *
 * Distinct from the CP `users/save-user` action so the consumer-side
 * surface stays edition-aware (Pro-resolved per-group policy applied
 * automatically — see `UserRules::defineRules()`) and never accidentally
 * exposes admin-only fields.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordChangeController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int|string>|bool|int authenticated users only — anonymous
     *     callers must use the password reset token flow.
     */
    protected array|bool|int $allowAnonymous = false;

    // Public Methods
    // =========================================================================

    /**
     * Saves a new password for the current logged-in user.
     *
     * Behavior:
     *  - 403 if no user logged in.
     *  - Re-renders the form with a `currentPassword` error when the
     *    submitted current password doesn't match the stored hash.
     *  - Re-renders form with errors when new password fails policy validation.
     *  - Redirects on success.
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
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();

        $user = Craft::$app->getUser()->getIdentity();

        if ($user === null) {
            throw new ForbiddenHttpException('You must be logged in to change your password.');
        }

        $request = Craft::$app->getRequest();
        $current = (string)$request->getRequiredBodyParam('currentPassword');
        $new = (string)$request->getRequiredBodyParam('newPassword');
        $confirm = (string)$request->getRequiredBodyParam('newPasswordConfirm');

        // Confirm match — let the controller short-circuit before any
        // expensive validation runs.
        if ($new !== $confirm) {
            $user->addError('newPasswordConfirm', Craft::t('app', 'Passwords don’t match.'));

            return $this->_failure($user);
        }

        // Validate the current password with a side-effect-free hash
        // compare instead of `User::authenticate()`. `authenticate()` would:
        //  - return FALSE for a CORRECT password when `passwordResetRequired`
        //    is set, locking out the very expired/reset-required users this
        //    flow is meant to serve;
        //  - fire `EVENT_BEFORE_AUTHENTICATE` (HIBP-on-login + breach
        //    notification / audit against the discarded OLD password) and
        //    `handleInvalidLogin()` (lockout penalties) as side effects of a
        //    password CHANGE, which is the wrong surface for those hooks.
        // `validatePassword()` throws `InvalidArgumentException` when the
        // stored hash is null/blank — treat that as a failed check.
        try {
            $currentMatches = Craft::$app->getSecurity()->validatePassword(
                $current,
                (string)$user->password,
            );
        } catch (InvalidArgumentException) {
            $currentMatches = false;
        }

        if (!$currentMatches) {
            $user->addError('currentPassword', Craft::t('app', 'Current password is incorrect.'));

            return $this->_failure($user);
        }

        // Set the new password — UserRules::defineRules() (registered via
        // User::EVENT_DEFINE_RULES) will run policy validation against the
        // resolved per-group/global policy.
        $user->newPassword = $new;

        if (!Craft::$app->getElements()->saveElement($user)) {
            // `saveElement()` populated `$user->getErrors()` already.
            return $this->_failure($user);
        }

        // Invalidate every other active session for this user. Craft's own
        // `User::afterSave` already runs this delete when `newPassword` is
        // set; we call it explicitly so the contract is visible at the call
        // site and survives any future Craft refactor. Current request's
        // session token is preserved — the user stays signed in here.
        PasswordPolicy::$plugin->getPasswords()->destroyOtherSessions($user);

        $message = Craft::t('password-policy', 'Your password has been updated.');

        // JSON callers get the message in the response body; only full-page
        // submits need the session flash (and the session is the wrong place
        // to write for an AJAX request — matches `asSuccess()`'s own JSON
        // short-circuit and the sibling CP controller's `_success()`).
        if ($this->request->getAcceptsJson()) {
            return $this->asSuccess($message);
        }

        Craft::$app->getSession()->setNotice($message);

        return $this->redirectToPostedUrl($user);
    }

    // Private Methods
    // =========================================================================

    /**
     * Re-renders the form with errors. The per-field error map lives on a
     * single channel — `$user->getErrors()` — surfaced two ways:
     *
     *  - For AJAX / JSON submits, `asModelFailure()` serializes the user
     *    model (errors included) into the response body.
     *  - For full-page submits, the errors are flashed under `pp:errors`
     *    so the redirected form render (and `PasswordChangeFormTag`'s
     *    error region) can read them off the session on the next request.
     *
     * Standardizing on `$user->getErrors()` avoids the prior split where a
     * controller-built `$errors` array and `saveElement()`'s own error map
     * disagreed depending on the failure branch.
     *
     * @param User $user the user being updated; errors already populated via
     *     `addError()` or `saveElement()`
     * @return Response|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _failure(User $user): ?Response
    {
        // For full-page (non-AJAX) submits, flash the per-field error map so
        // the redirected form render — and `PasswordChangeFormTag`'s
        // `role="alert"` error region — can read it off the session on the
        // next request. For JSON submits the errors ride in the response body
        // (`asModelFailure()` serializes `$user->getErrors()`), so the flash
        // would be dead weight; gating here also keeps the surface session-free
        // for AJAX callers, matching `asFailure()`'s own JSON short-circuit.
        if (!$this->request->getAcceptsJson()) {
            Craft::$app->getSession()->setFlash('pp:errors', $user->getErrors());
        }

        return $this->asModelFailure(
            $user,
            Craft::t('password-policy', 'Couldn’t update password.'),
            'user',
        );
    }
}
