<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\actions;

use Craft;
use craft\base\ElementAction;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;

/**
 * Class SendPasswordResetEmail
 *
 * Element action that sends Craft's standard "forgot password" email to
 * one or more selected users via `Users::sendPasswordResetEmail()`. The
 * recipient clicks the link, lands on Craft's set-password page, and
 * sets a new password — at which point the central history-write
 * listener consumes the pending `AdminForceReset` reason this action
 * pinned and records the new history row with `changeReason =
 * admin_force_reset`.
 *
 * Distinct from `ForcePasswordReset`: that action flips
 * `passwordResetRequired = true` so the user is force-reset on next
 * login. This one mails the link directly. Operators may use them
 * together (mail the link AND flag the next-login force) or separately
 * depending on workflow.
 *
 * Bulk-friendly — sending reset links to N users is fine; per-user
 * pending reasons are written independently. Capture is non-negotiable
 * across editions; gates apply to UI/API/SIEM exposure downstream
 * (memory rule `project_audit_capture_principle.md`).
 *
 * Permission: `pp:change-user-passwords` — same gate as
 * `ChangeUserPassword`. Both are admin-on-user operations on the same
 * surface; one permission per pair keeps the matrix small.
 *
 * Read-only mode: when `allowAdminChanges = false`, `getTriggerHtml()`
 * returns null so the action never registers on the index. The
 * action also defends-in-depth in `performAction()` by checking
 * permission before iterating.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SendPasswordResetEmail extends ElementAction
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the action's trigger label.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTriggerLabel(): string
    {
        return Craft::t('password-policy', 'Send password reset email');
    }

    /**
     * Returns the confirmation message shown before the action runs.
     *
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getConfirmationMessage(): ?string
    {
        return Craft::t(
            'password-policy',
            'Are you sure you want to send a password reset email to the selected users?',
        );
    }

    /**
     * Returns the trigger HTML rendered into the index actions menu.
     *
     * Defaults to the standard confirm-dialog flow (no custom JS) when
     * read-only mode is off; returns `null` when read-only mode is on
     * so the trigger never registers.
     *
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTriggerHtml(): ?string
    {
        if (!Craft::$app->getConfig()->getGeneral()->allowAdminChanges) {
            return null;
        }

        // Standard confirm-dialog flow — no custom JS needed. Returning
        // null here lets `ElementAction`'s default trigger plumbing
        // (confirm message + bulk-friendly POST to performAction) take
        // over.
        return null;
    }

    /**
     * Performs the action over the queried user set.
     *
     * For each selected user:
     *  1. Pins a pending `AdminForceReset` reason on user_state — the
     *     user's NEXT password change will record `changeReason =
     *     admin_force_reset` in history. Capture happens on every
     *     edition.
     *  2. Calls `Users::sendPasswordResetEmail()` to mail the standard
     *     Craft reset link.
     *
     * Per-user soft-fail — a single failed send doesn't abort the rest
     * of the batch. Final message lists the success count + failure
     * count so the operator sees what happened.
     *
     * Defense-in-depth permission check: the action's trigger only
     * registers for users with the permission, but the controller
     * registration also reaches `performAction()` from any caller that
     * bypasses the trigger (e.g. console + Craft internals). Reject
     * those calls explicitly with a `ForbiddenHttpException`-shaped
     * failure rather than silently passing.
     *
     * @param ElementQueryInterface $query
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function performAction(ElementQueryInterface $query): bool
    {
        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser === null || !$currentUser->can('pp:change-user-passwords')) {
            $this->setMessage(Craft::t(
                'password-policy',
                'You don’t have permission to send password reset emails.',
            ));
            return false;
        }

        if (!Craft::$app->getConfig()->getGeneral()->allowAdminChanges) {
            $this->setMessage(Craft::t(
                'app',
                'Administrative changes are disallowed in this environment.',
            ));
            return false;
        }

        /** @var User[] $users */
        $users = $query->all();
        $usersService = Craft::$app->getUsers();
        $userState = PasswordPolicy::$plugin->getUserState();

        $sentCount = 0;
        $failCount = 0;

        foreach ($users as $user) {
            try {
                // Pin the pending reason BEFORE the email send so the user_state
                // row reflects intent even if the SMTP transport fails. The
                // listener consumes the reason on the user's next change; a
                // never-completed change just leaves a harmless pending row.
                $userState->setPendingReason($user, ChangeReason::AdminForceReset);

                if ($usersService->sendPasswordResetEmail($user)) {
                    $sentCount++;
                } else {
                    $failCount++;
                }
            } catch (Throwable $e) {
                $failCount++;
                Craft::warning(
                    'Failed to send password reset email to user #' . $user->id . ': ' . $e->getMessage(),
                    'password-policy',
                );
            }
        }

        if ($sentCount === 0 && $failCount > 0) {
            $this->setMessage(Craft::t(
                'password-policy',
                'Could not send password reset emails to any selected users.',
            ));
            return false;
        }

        if ($failCount > 0) {
            $this->setMessage(Craft::t(
                'password-policy',
                '{count, number} {count, plural, =1{email} other{emails}} sent. {failed, number} failed.',
                ['count' => $sentCount, 'failed' => $failCount],
            ));
            return true;
        }

        $this->setMessage(Craft::t(
            'password-policy',
            '{count, number} password reset {count, plural, =1{email} other{emails}} sent.',
            ['count' => $sentCount],
        ));

        return true;
    }
}
