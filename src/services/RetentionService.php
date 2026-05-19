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
     * Flags a user as requiring a password reset.
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
}
