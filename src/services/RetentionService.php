<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\base\Component;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User as UserElement;
use craft\helpers\Queue;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\jobs\PasswordResetJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\db\Exception;

/**
 * Class RetentionService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class RetentionService extends Component
{
    // Public Properties
    // =========================================================================

    /**
     * @var int
     */
    public int $resets = 0;

    // Public Methods
    // =========================================================================

    /**
     * Pushes a password reset job to the queue.
     *
     * @return void
     *
     * @author CraftPulse
     */
    public function resetPasswords(): void
    {
        Queue::push(
            job: new PasswordResetJob([
                'description' => Craft::t('password-policy', 'Resetting passwords'),
            ]),
            priority: 10,
            ttr: 300,
            queue: PasswordPolicy::$plugin->queue,
        );
    }

    /**
     * Flags a user as requiring a password reset — the write behind the
     * MASS path, reached only for accounts a retention sweep already
     * found expired (the Password Retention utility, the
     * `retention/force-reset-passwords` console command, and
     * `PasswordResetJob`).
     *
     * Admin accounts are skipped, silently and deliberately: that has
     * been the behaviour since the plugin had no editions, and a
     * retention sweep locking every administrator out at once is not a
     * failure mode worth introducing. The Pro per-user path handles named
     * targets, admins included, through
     * {@see self::forceResetForUser()} behind
     * {@see SecurityService::canManageUserCredentials()}.
     *
     * @param UserElement $user
     * @return void
     *
     * @throws Throwable
     *
     * @author CraftPulse
     */
    public function requirePasswordReset(UserElement $user): void
    {
        // In the free version we will never force the reset of our admin accounts
        if (!$user->admin) {
            $user->passwordResetRequired = true;
            Craft::$app->getElements()->saveElement($user);
            $this->resets++;

            // Pin a pending `ExpiryForced` reason on the user_state row so
            // the user's NEXT password change records the right
            // `changeReason` in history. Capture is non-negotiable across
            // editions — Lite, Pro, and Enterprise installs all populate
            // this row (memory rule `project_audit_capture_principle.md`).
            PasswordPolicy::$plugin->getUserState()->setPendingReason(
                $user,
                ChangeReason::ExpiryForced,
            );

            // Audit log: force reset
            PasswordPolicy::$plugin->getAuditLog()->logEvent(
                userId: $user->id,
                event: 'password_reset_forced',
                outcome: 'success',
                source: null,
            );
        }
    }

    /**
     * Forces a password reset on one named user — the Pro per-user path,
     * additive to the universal mass path in
     * {@see self::requirePasswordReset()}.
     *
     * Differences from the mass path, both deliberate:
     *
     *  - It flags the target whether or not the password has expired.
     *    That is the capability Pro adds.
     *  - It pins `ChangeReason::AdminForceReset` rather than
     *    `ChangeReason::ExpiryForced`, because an operator pointed at
     *    this account rather than a retention sweep reaching it.
     *
     * Callers MUST clear {@see SecurityService::canManageUserCredentials()}
     * first — this method performs no authorization of its own, so that admin
     * targets remain reachable to admin actors.
     *
     * Audit parity with the mass path: the same `password_reset_forced`
     * event is written to the audit chain. Capture is universal across
     * editions.
     *
     * @param UserElement $target
     * @return bool whether the flag was newly set (false when the user
     *     was already flagged, which is a no-op rather than a failure)
     *
     * @throws Throwable if the user element fails to save.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function forceResetForUser(UserElement $target): bool
    {
        if ($this->_isPasswordResetRequired((int)$target->id)) {
            return false;
        }

        $target->passwordResetRequired = true;
        Craft::$app->getElements()->saveElement($target, false);
        $this->resets++;

        // Pin the pending reason BEFORE anything else consumes the slot so
        // the target's next password change records `admin_force_reset` in
        // history. Capture is non-negotiable across editions — Lite, Pro,
        // and Enterprise installs all populate this row (memory rule
        // `project_audit_capture_principle.md`).
        PasswordPolicy::$plugin->getUserState()->setPendingReason(
            $target,
            ChangeReason::AdminForceReset,
        );

        PasswordPolicy::$plugin->getAuditLog()->logEvent(
            userId: $target->id,
            event: 'password_reset_forced',
            outcome: 'success',
            source: null,
        );

        return true;
    }

    /**
     * Resets passwords for all users in a specific group.
     *
     * @param int $groupId
     * @return int The number of users reset
     *
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resetPasswordsByGroup(int $groupId): int
    {
        $users = UserElement::find()
            ->groupId($groupId)
            ->status(null)
            ->all();

        $count = 0;

        foreach ($users as $user) {
            if (!$user->admin && !$user->passwordResetRequired) {
                $this->requirePasswordReset($user);
                $count++;
            }
        }

        return $count;
    }

    /**
     * Invalidates all sessions for a user by deleting their session tokens.
     *
     * Craft stores auth tokens in the DB (Table::SESSIONS) regardless of
     * PHP session backend (Redis, files, etc.). Deleting rows forces
     * re-authentication on next request.
     *
     * @param int $userId
     * @param string|null $excludeToken Current session token to preserve (for admin context)
     * @return int The number of sessions invalidated
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function invalidateUserSessions(int $userId, ?string $excludeToken = null): int
    {
        $condition = ['userId' => $userId];

        // In web context, preserve the current admin's session
        if ($excludeToken !== null) {
            $condition = ['and', $condition, ['not', ['token' => $excludeToken]]];
        }

        return Craft::$app->getDb()->createCommand()
            ->delete(Table::SESSIONS, $condition)
            ->execute();
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns whether the persisted `users.passwordResetRequired` column
     * is set for the given user id.
     *
     * `craft\elements\db\UserQuery::beforePrepare()` does not
     * `addSelect()` the column, so the in-memory
     * `$user->passwordResetRequired` reads `false` on a freshly loaded
     * element regardless of database state (same gotcha as
     * `lastPasswordChangeDate`). Every already-flagged short-circuit
     * therefore has to read the column directly, or a redundant operator
     * click would clobber an in-flight pending reason (`BreachForced`
     * from HIBP-on-login, `ExpiryForced` from cron) with
     * `AdminForceReset`.
     *
     * @param int $userId
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _isPasswordResetRequired(int $userId): bool
    {
        return (bool)(new Query())
            ->select(['passwordResetRequired'])
            ->from(Table::USERS)
            ->where(['id' => $userId])
            ->scalar();
    }
}
