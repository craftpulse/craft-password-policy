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
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;

/**
 * Class ResendNotification
 *
 * Bulk element action that re-fires previously-logged notifications.
 * Delegates per-row to
 * {@see \craftpulse\passwordpolicy\services\NotificationService::resend()},
 * which re-renders the template fresh from current state — admin
 * template edits since the original send DO show up — and writes a
 * new element row linked to the original via `resentFromId`.
 *
 * Returns false (with a useful message) when any selected row is not
 * resendable. Mailer-key sources (`new_device`, `admin_alert_*`) lack
 * the original event payload that would let the service re-render;
 * those rows skip rather than fail loudly.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ResendNotification extends ElementAction
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getConfirmationMessage(): ?string
    {
        return Craft::t(
            'password-policy',
            'Are you sure you want to resend the selected notifications? The current template will be re-rendered.',
        );
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTriggerLabel(): string
    {
        return Craft::t('password-policy', 'Resend');
    }

    /**
     * @inheritdoc
     *
     * Iterates the selected element query, calls
     * {@see \craftpulse\passwordpolicy\services\NotificationService::resend()}
     * on each row, and accumulates a single user-facing summary. The
     * service returns false on non-resendable rows (mailer-key types)
     * without throwing; those count toward `$skippedCount`.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function performAction(ElementQueryInterface $query): bool
    {
        /** @var NotificationLogElement[] $rows */
        $rows = $query->all();

        $service = PasswordPolicy::$plugin->getNotification();

        $successCount = 0;
        $skippedCount = 0;
        $failedCount = 0;

        foreach ($rows as $row) {
            try {
                if ($service->resend($row)) {
                    $successCount++;
                } else {
                    $skippedCount++;
                }
            } catch (Throwable $e) {
                Craft::error(
                    "Failed to resend notification #{$row->id}: " . $e->getMessage(),
                    'password-policy',
                );

                $failedCount++;
            }
        }

        if ($failedCount > 0) {
            $this->setMessage(Craft::t(
                'password-policy',
                'Could not resend all notifications: {failed} failed, {success} succeeded, {skipped} skipped (not resendable).',
                [
                    'failed' => $failedCount,
                    'success' => $successCount,
                    'skipped' => $skippedCount,
                ],
            ));

            return false;
        }

        if ($skippedCount > 0 && $successCount === 0) {
            $this->setMessage(Craft::t(
                'password-policy',
                'No notifications were resendable. Mailer-key sources (new device, admin alerts) need the original event payload.',
            ));

            return false;
        }

        $this->setMessage(Craft::t(
            'password-policy',
            '{success, number} {success, plural, =1{notification} other{notifications}} resent. {skipped, plural, =0{} =1{# row skipped (not resendable).} other{# rows skipped (not resendable).}}',
            [
                'success' => $successCount,
                'skipped' => $skippedCount,
            ],
        ));

        return true;
    }
}
