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
use craft\helpers\App;
use craftpulse\passwordpolicy\models\NotificationTemplateModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use RuntimeException;
use Throwable;
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
     * Pro-only — Lite throws because the editable templates surface (which
     * this method drives) is gated to Pro and there's no fallback shape on
     * Lite. Callers (queue job, console command, web controller) all guard
     * on Pro before reaching here.
     *
     * @param User $user
     * @param int $daysRemaining
     * @return void
     *
     * @throws RuntimeException when the plugin is running the Lite edition
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendPasswordExpiryReminder(User $user, int $daysRemaining): void
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new RuntimeException('Password expiry reminders require the Pro edition.');
        }

        if ($user->email === null) {
            return;
        }

        // Check dedup — only send once per expiry window
        if ($this->_hasRecentNotification($user->id, 'expiry_reminder')) {
            return;
        }

        $siteId = $this->_resolveSiteIdForUser($user);
        $template = PasswordPolicy::$plugin->getNotificationTemplates()
            ->getTemplate('expiry-reminder', $siteId);

        if ($template === null) {
            Craft::warning(
                "No expiry-reminder template found for user {$user->id} (siteId {$siteId})",
                'password-policy',
            );
            return;
        }

        try {
            $message = $this->composeFromTemplate($template, $user, [
                'user' => $user,
                'daysUntilExpiry' => $daysRemaining,
                'siteName' => Craft::$app->getSites()->getSiteById($siteId)?->getName()
                    ?? Craft::$app->getSystemName(),
            ]);

            $message->setTo($user->email)->send();

            $this->_logNotification($user->id, 'expiry_reminder');
        } catch (Throwable $e) {
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

    /**
     * Renders a template against the given vars and applies sender-overrides
     * (or the system mailer defaults when overrides aren't set).
     *
     * The plain `body` field is sent as text/plain — there is no HTML body.
     * Subject and body are both Twig sources rendered through Craft's
     * shared view component, so token substitution works the same on the
     * test-send AJAX path as on the queue-driven send path.
     *
     * Public so the test-send web controller can use the same render
     * pipeline; `sendPasswordExpiryReminder()` calls this internally too.
     *
     * @param NotificationTemplateModel $template the template to render
     * @param User $user the recipient (used as `from` for elevated session)
     * @param array<string, mixed> $vars Twig render context
     * @return \craft\mail\Message
     *
     * @throws Throwable when Twig fails to render
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function composeFromTemplate(NotificationTemplateModel $template, User $user, array $vars): \craft\mail\Message
    {
        $view = Craft::$app->getView();

        $subject = $view->renderString($template->subject, $vars);
        $body = $view->renderString($template->body, $vars);

        $mailer = Craft::$app->getMailer();
        $message = $mailer->compose()
            ->setSubject($subject)
            ->setTextBody($body);

        $fromName = $template->senderName !== null
            ? App::parseEnv($template->senderName)
            : null;
        $fromEmail = $template->senderEmail !== null
            ? App::parseEnv($template->senderEmail)
            : null;

        if ($fromEmail !== null && $fromEmail !== '') {
            $message->setFrom([$fromEmail => $fromName ?: $fromEmail]);
        }

        if ($template->replyTo !== null) {
            $replyTo = App::parseEnv($template->replyTo);
            if ($replyTo !== '') {
                $message->setReplyTo($replyTo);
            }
        }

        return $message;
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

    /**
     * Resolves the site ID a user's notifications should render under.
     *
     * Strategy: match the user's `preferredLanguage` to a site's language;
     * fall back to the primary site when nothing matches (or when the user
     * has no preferred language set, e.g. front-end-only accounts).
     *
     * @param User $user
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveSiteIdForUser(User $user): int
    {
        $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
        $preferredLanguage = $user->getPreferredLanguage();

        if ($preferredLanguage === null) {
            return $primarySiteId;
        }

        foreach (Craft::$app->getSites()->getAllSites() as $site) {
            if ($site->language === $preferredLanguage) {
                return $site->id;
            }
        }

        return $primarySiteId;
    }
}
