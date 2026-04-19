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
     * Performs the action on the given element query.
     *
     * Sets `passwordResetRequired = true` on each selected user and saves.
     *
     * @param ElementQueryInterface $query
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function performAction(ElementQueryInterface $query): bool
    {
        /** @var User[] $users */
        $users = $query->all();
        $elementsService = Craft::$app->getElements();
        $successCount = 0;

        foreach ($users as $user) {
            if ($user->passwordResetRequired) {
                $successCount++;
                continue;
            }

            try {
                $user->passwordResetRequired = true;
                $elementsService->saveElement($user, false);
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
}
