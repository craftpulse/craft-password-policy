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
use Throwable;
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
     *  - 401 if no user logged in.
     *  - 400 if `currentPassword` doesn't match.
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
            return $this->_failure($user, ['newPasswordConfirm' => Craft::t('app', 'Passwords don’t match.')]);
        }

        // Validate the current password — we let User::authenticate() do
        // the work because it already understands suspended/locked/etc.
        // states and never leaks timing info between right-but-locked and
        // wrong-password.
        if (!$user->authenticate($current)) {
            return $this->_failure($user, ['currentPassword' => Craft::t('app', 'Current password is incorrect.')]);
        }

        // Set the new password — UserRules::defineRules() (registered via
        // User::EVENT_DEFINE_RULES) will run policy validation against the
        // resolved per-group/global policy.
        $user->newPassword = $new;

        if (!Craft::$app->getElements()->saveElement($user)) {
            return $this->_failure($user, $user->getErrors());
        }

        Craft::$app->getSession()->setNotice(
            Craft::t('password-policy', 'Your password has been updated.'),
        );

        return $this->redirectToPostedUrl($user);
    }

    // Private Methods
    // =========================================================================

    /**
     * Re-renders the form with errors and a session error flash. Lets the
     * consumer template inspect `getFlash('error')` and the user's
     * `getErrors()` map to render per-field error UI.
     *
     * @param User $user the user being updated
     * @param array<string, mixed> $errors the per-field error map
     * @return Response|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _failure(User $user, array $errors): ?Response
    {
        Craft::$app->getSession()->setError(
            Craft::t('password-policy', 'Couldn’t update password.'),
        );

        // Flash the per-field errors so the consumer template can render them.
        Craft::$app->getSession()->setFlash('errors', $errors);

        return $this->asModelFailure(
            $user,
            Craft::t('password-policy', 'Couldn’t update password.'),
            'user',
        );
    }
}
