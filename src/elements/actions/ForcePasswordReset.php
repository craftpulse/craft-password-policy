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
use craft\db\Query;
use craft\db\Table;
use craft\elements\db\ElementQueryInterface;
use craft\elements\User;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;

use Throwable;

/**
 * Class ForcePasswordReset
 *
 * Bulk element action that flags selected users as requiring a password reset
 * on their next login.
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
     * Sets `passwordResetRequired = true` on each selected user and saves.
     *
     * Defense-in-depth gate: the trigger only registers for users with
     * `pp:force-reset-passwords` when admin changes are allowed, but
     * `performAction()` is reachable by any caller that bypasses the
     * trigger (Craft internals, crafted POSTs). Reject those explicitly
     * — require the force-reset permission AND `allowAdminChanges` before
     * mutating any user, matching the `SendPasswordResetEmail` guard.
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

        if ($currentUser === null || !$currentUser->can('pp:force-reset-passwords')) {
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
        $elementsService = Craft::$app->getElements();
        $successCount = 0;

        $userState = PasswordPolicy::$plugin->getUserState();

        // `UserQuery::beforePrepare()` does NOT addSelect
        // `passwordResetRequired`, so the in-memory `$user->passwordResetRequired`
        // is always `false` regardless of the DB column. Same gotcha as
        // `lastPasswordChangeDate` (memory gap #9). Pre-load the persisted
        // column for the queried user IDs so the short-circuit skips users
        // already flagged — otherwise we'd clobber any in-flight pending
        // reason (BreachForced from HIBP-on-login, ExpiryForced from cron)
        // with `AdminForceReset` on a redundant admin click.
        $persistedFlags = $this->_loadPasswordResetFlags(
            array_map(static fn(User $u): int => (int)$u->id, $users),
        );

        foreach ($users as $user) {
            if ($persistedFlags[$user->id] ?? false) {
                $successCount++;
                continue;
            }

            try {
                $user->passwordResetRequired = true;
                $elementsService->saveElement($user, false);

                // Pin a pending `AdminForceReset` reason on the user_state
                // row so the user's NEXT password change records the right
                // `changeReason` in history. Capture is non-negotiable
                // across editions — Lite, Pro, and Enterprise installs all
                // populate this row (memory rule
                // `project_audit_capture_principle.md`).
                $userState->setPendingReason($user, ChangeReason::AdminForceReset);

                $successCount++;
            } catch (Throwable) {
                Craft::warning(
                    "Failed to set passwordResetRequired for user #{$user->id}.",
                    'password-policy',
                );
            }
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

    // Private Methods
    // =========================================================================

    /**
     * Returns a map of `[userId => bool]` reflecting the persisted
     * `users.passwordResetRequired` column for every queried user.
     *
     * Workaround for `UserQuery::beforePrepare()` not addSelect-ing the
     * column — without this the in-memory User element always reads as
     * `false` regardless of DB state, and the bulk action's
     * already-flagged short-circuit would never fire.
     *
     * @param int[] $userIds
     * @return array<int, bool> map keyed by userId
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _loadPasswordResetFlags(array $userIds): array
    {
        if (empty($userIds)) {
            return [];
        }

        $rows = (new Query())
            ->select(['id', 'passwordResetRequired'])
            ->from(Table::USERS)
            ->where(['id' => $userIds])
            ->all();

        $flags = [];

        foreach ($rows as $row) {
            $flags[(int)$row['id']] = (bool)$row['passwordResetRequired'];
        }

        return $flags;
    }
}
