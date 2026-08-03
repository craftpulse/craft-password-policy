<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\actions;

use Craft;
use craft\base\ElementAction;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;

use Throwable;

/**
 * Class ForcePasswordReset
 *
 * Bulk element action that flags selected users as requiring a password reset
 * on their next login. One of the three per-user (Pro) force-reset surfaces,
 * alongside the user-edit action menu and the Password Security screen's
 * Actions pane. Unlike the universal mass path it reaches named accounts
 * whether or not their passwords have expired.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ForcePasswordReset extends ElementAction
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
        return Craft::t('password-policy', 'Force Password Reset');
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
            'Are you sure you want to force a password reset for the selected users?'
        );
    }

    /**
     * Returns the trigger HTML rendered into the index actions menu.
     *
     * Returns `null` when `allowAdminChanges` is disabled so the trigger
     * never registers on the element index in a read-only environment —
     * mirrors the `SendPasswordResetEmail` sibling. When admin changes are
     * allowed, returning `null` lets `ElementAction`'s default confirm-
     * dialog plumbing take over (no custom JS needed).
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

        return null;
    }

    /**
     * Performs the action on the given element query.
     *
     * Sets `passwordResetRequired = true` on each selected user, pins an
     * `AdminForceReset` pending reason, and writes a
     * `password_reset_forced` audit event — all three via
     * `RetentionService::forceResetForUser()`, so this surface records the
     * same trail the mass path does.
     *
     * Defense-in-depth gates: the trigger only registers on Pro, for
     * users holding {@see PasswordPolicy::PERMISSION_USER_FORCE_RESET},
     * when admin changes are allowed. `performAction()` is reachable by
     * any caller that bypasses the trigger (Craft internals, crafted
     * POSTs), so all three are re-checked here, and the peer-admin guard
     * runs per selected target — a bulk selection is exactly the shape a
     * non-admin would use to sweep an admin in alongside legitimate
     * targets.
     *
     * @param ElementQueryInterface $query
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function performAction(ElementQueryInterface $query): bool
    {
        $plugin = PasswordPolicy::$plugin;
        $currentUser = Craft::$app->getUser()->getIdentity();

        if (!$plugin->getIsPro()) {
            $this->setMessage(Craft::t(
                'password-policy',
                'You don’t have permission to force a password reset.',
            ));
            return false;
        }

        if ($currentUser === null || !$currentUser->can(PasswordPolicy::PERMISSION_USER_FORCE_RESET)) {
            $this->setMessage(Craft::t(
                'password-policy',
                'You don’t have permission to force a password reset.',
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
        $retention = $plugin->retention;
        $successCount = 0;
        $deniedCount = 0;

        foreach ($users as $user) {
            // Peer-admin guard, per target. A non-admin holding the grant may
            // not force a reset on an admin, so an admin swept into the
            // selection is refused rather than quietly skipped.
            if (!$retention->canForceResetUser($user, $currentUser)) {
                $deniedCount++;
                continue;
            }

            try {
                // Returns false when the user is already flagged, which is a
                // no-op rather than a failure: re-pinning would clobber an
                // in-flight pending reason (`BreachForced` from HIBP-on-login,
                // `ExpiryForced` from cron) with `AdminForceReset`.
                $retention->forceResetForUser($user);
                $successCount++;
            } catch (Throwable) {
                Craft::warning(
                    "Failed to set passwordResetRequired for user #{$user->id}.",
                    'password-policy',
                );
            }
        }

        if ($deniedCount > 0) {
            $this->setMessage(Craft::t(
                'password-policy',
                'Only an admin can force a password reset on another admin.',
            ));
            return false;
        }

        if ($successCount !== count($users)) {
            $this->setMessage(
                Craft::t('password-policy', 'Could not force password reset for all users.')
            );
            return false;
        }

        $this->setMessage(
            Craft::t(
                'password-policy',
                '{count, number} {count, plural, =1{user} other{users}} flagged for password reset.',
                ['count' => $successCount],
            )
        );

        return true;
    }
}
