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

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class NotificationService
 *
 * Handles email notifications for password expiry reminders, new device alerts,
 * and admin security alerts. Tracks sent notifications for dedup.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Sends a password expiry reminder to a user.
     *
     * @param User $user
     * @param int $daysRemaining
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendPasswordExpiryReminder(User $user, int $daysRemaining): void
    {
        if ($user->email === null) {
            return;
        }

        // Check dedup — only send once per expiry window
        if ($this->_hasRecentNotification($user->id, 'expiry_reminder')) {
            return;
        }

        try {
            Craft::$app->getMailer()
                ->composeFromKey('password-policy:expiry-reminder', [
                    'user' => $user,
                    'daysRemaining' => $daysRemaining,
                ])
                ->setTo($user->email)
                ->send();

            $this->_logNotification($user->id, 'expiry_reminder');
        } catch (\Throwable $e) {
            Craft::error(
                "Failed to send expiry reminder to user {$user->id}: " . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Sends a new device login alert to a user.
     *
     * @param User $user
     * @param string $deviceLabel
     * @param string $maskedIp
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendNewDeviceAlert(User $user, string $deviceLabel, string $maskedIp): void
    {
        if ($user->email === null) {
            return;
        }

        try {
            Craft::$app->getMailer()
                ->composeFromKey('password-policy:new-device-alert', [
                    'user' => $user,
                    'deviceLabel' => $deviceLabel,
                    'maskedIp' => $maskedIp,
                ])
                ->setTo($user->email)
                ->send();

            $this->_logNotification($user->id, 'new_device');
        } catch (\Throwable $e) {
            Craft::error(
                "Failed to send new device alert to user {$user->id}: " . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Sends an admin security alert.
     *
     * @param string $event
     * @param array $context
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendAdminSecurityAlert(string $event, array $context = []): void
    {
        $settings = PasswordPolicy::$plugin->getSettings();
        $email = Craft::parseEnv($settings->adminAlertEmail);

        if (empty($email)) {
            return;
        }

        // Check if this event type triggers alerts
        if ($settings->adminAlertEvents !== null && !in_array($event, $settings->adminAlertEvents, true)) {
            return;
        }

        // Dedup: no duplicate alerts for same event within 5 minutes
        $recentCount = (new Query())
            ->from('{{%passwordpolicy_notification_log}}')
            ->where([
                'notificationType' => 'admin_alert_' . $event,
            ])
            ->andWhere(['>=', 'sentAt', Carbon::now('UTC')->subMinutes(5)->format('Y-m-d H:i:s')])
            ->count();

        if ((int)$recentCount > 0) {
            return;
        }

        try {
            Craft::$app->getMailer()
                ->composeFromKey('password-policy:admin-security-alert', [
                    'event' => $event,
                    'context' => $context,
                ])
                ->setTo($email)
                ->send();

            // Log with userId=0 for admin alerts (no specific user)
            $this->_logNotification(0, 'admin_alert_' . $event);
        } catch (\Throwable $e) {
            Craft::error(
                "Failed to send admin security alert for {$event}: " . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Purges old notification log entries.
     *
     * @param int $daysToKeep
     * @return int The number of entries purged
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function pruneOldEntries(int $daysToKeep = 30): int
    {
        $threshold = Carbon::now('UTC')->subDays($daysToKeep)->format('Y-m-d H:i:s');

        return Craft::$app->getDb()->createCommand()
            ->delete('{{%passwordpolicy_notification_log}}', ['<', 'sentAt', $threshold])
            ->execute();
    }

    // Private Methods
    // =========================================================================

    /**
     * Checks if a recent notification of the given type was sent to the user.
     *
     * @param int $userId
     * @param string $type
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hasRecentNotification(int $userId, string $type): bool
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        // For expiry reminders, check within the reminder window
        $window = $settings->expiryReminderDays;
        $threshold = Carbon::now('UTC')->subDays($window)->format('Y-m-d H:i:s');

        return (new Query())
            ->from('{{%passwordpolicy_notification_log}}')
            ->where([
                'userId' => $userId,
                'notificationType' => $type,
            ])
            ->andWhere(['>=', 'sentAt', $threshold])
            ->exists();
    }

    /**
     * Records a sent notification for dedup tracking.
     *
     * @param int $userId
     * @param string $type
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _logNotification(int $userId, string $type): void
    {
        try {
            Craft::$app->getDb()->createCommand()
                ->insert('{{%passwordpolicy_notification_log}}', [
                    'userId' => $userId,
                    'notificationType' => $type,
                    'sentAt' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                ])
                ->execute();
        } catch (\Throwable $e) {
            Craft::error(
                "Failed to log notification: " . $e->getMessage(),
                'password-policy',
            );
        }
    }
}
