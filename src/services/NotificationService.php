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
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\models\NotificationTemplateModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateTime;
use RuntimeException;
use Throwable;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class NotificationService
 *
 * Sends password expiry reminders, breach detection alerts, new-device
 * alerts, and admin security alerts; tracks every send attempt — both
 * successes and failures — in `passwordpolicy_notification_log`.
 *
 * **Audit invariant:** the log row write happens on BOTH branches of
 * the `mailer->send()` outcome — a successful send writes
 * `status = sent` with rendered subject + body; a failed send writes
 * `status = failed` with `errorMessage`. The pre-Phase-F2 behavior
 * (row only on success, failures only logged to the plugin log file)
 * was a side-effect dedup substrate that pretended to be an audit
 * table — operators couldn't see failures at all.
 *
 * **Dedup substrate (G7).** Per-(eventClass, cooldownKey) suppression
 * lives in `passwordpolicy_alert_cooldowns` via `AlertCooldownService`.
 * `_hasRecentNotification()` and `sendAdminSecurityAlert()`'s old 5-min
 * inline filter both delegate now. Semantic flip from F2: the cooldown
 * row is recorded on the dispatch ATTEMPT regardless of outcome — a
 * failed-then-retried call inside the window is suppressed. Operators
 * get one attempt per window, full stop. Admin override path for the
 * rare retry-after-fail case is `resend()` (bypasses the cooldown gate
 * explicitly).
 *
 * Capture is non-negotiable across editions — Lite installs already
 * write rows for the surfaces they have (admin security alerts —
 * Lite-eligible). The activity-surface CP screen is gated to Pro+
 * via the existing Notifications subnav permission, but the table
 * itself is populated everywhere.
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

        // Check dedup — only send once per expiry window. Filters on
        // status='sent' so failed-then-retried doesn't suppress.
        if ($this->_hasRecentNotification($user->id, 'expiry_reminder')) {
            return;
        }

        $this->_dispatch(
            user: $user,
            type: 'expiry_reminder',
            templateKey: 'expiry-reminder',
            extraVars: [
                'daysUntilExpiry' => $daysRemaining,
            ],
        );
    }

    /**
     * Sends a `breach-detected` notification to a user whose password
     * was just found in the HIBP breach database during login.
     *
     * Pro-only — the listener that drives this method only registers
     * on Pro, but the guard is duplicated here as defense-in-depth in
     * case a future caller invokes the method directly.
     *
     * Dedup is handled by the listener (cache-based, 24h) — by the
     * time we reach here, the same (user, prefix) hasn't notified
     * within the last day. We still write a notification_log row so
     * admins have a historical trail in the same place expiry-
     * reminder logs land.
     *
     * @param User $user the user whose password matched
     * @param DateTime $detectedAt when the match was detected
     * @return void
     *
     * @throws RuntimeException when the plugin is running the Lite edition
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendBreachDetected(User $user, DateTime $detectedAt): void
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new RuntimeException('HIBP-on-login notifications require the Pro edition.');
        }

        if ($user->email === null) {
            return;
        }

        $this->_dispatch(
            user: $user,
            type: 'breach_detected',
            templateKey: 'breach-detected',
            extraVars: [
                'detectedAt' => $detectedAt,
            ],
        );
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

        // `composeFromKey` path (mailer-templates.php) — distinct from
        // the editable-templates surface used by expiry / breach.
        // Subject + body capture is intentionally omitted for mailer-
        // key sources: the rendered content lives inside the Symfony
        // Message and isn't trivially extractable, and the operator-
        // visibility value is low because these templates aren't
        // admin-edited. Phase G adds new-device + admin-alert to the
        // editable-templates surface; at that point this path moves
        // to `_dispatch()` and gets full capture.
        $message = Craft::$app->getMailer()->composeFromKey('password-policy:new-device-alert', [
            'user' => $user,
            'deviceLabel' => $deviceLabel,
            'maskedIp' => $maskedIp,
        ]);

        $this->_dispatchMailerKey(
            userId: $user->id,
            type: 'new_device',
            recipient: $user->email,
            sender: $message,
        );
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

        // Dedup: no duplicate alerts for same event within the cooldown
        // window. Pre-G7 this was an inline `Query` against
        // `notification_log` filtering on `status = 'sent'` within a
        // hardcoded 5-minute window — same window is now configurable
        // via `AlertCooldownService::DEFAULT_COOLDOWN_ADMIN_SECURITY_ALERT`
        // (still 300 seconds default).
        //
        // The `!shouldFire()` polarity matches `_hasRecentNotification()`'s
        // semantic flip — see that method for the documented rationale.
        if (!PasswordPolicy::$plugin->getAlertCooldown()->shouldFire(
            'admin_security_alert:' . $event,
            'event:' . $event,
            AlertCooldownService::DEFAULT_COOLDOWN_ADMIN_SECURITY_ALERT,
        )) {
            return;
        }

        $message = Craft::$app->getMailer()->composeFromKey('password-policy:admin-security-alert', [
            'event' => $event,
            'context' => $context,
        ]);

        // Log with userId=null for admin alerts (no specific user).
        // userId is nullable since 5.2.0 — the same column that flips
        // to `SET NULL` on user hard-delete also accepts NULL for
        // not-tied-to-a-user admin events.
        $this->_dispatchMailerKey(
            userId: null,
            type: 'admin_alert_' . $event,
            recipient: $email,
            sender: $message,
        );
    }

    /**
     * Re-sends a previously logged notification.
     *
     * Re-renders the template **fresh** from current state (admin may
     * have edited the template since the original send) and writes a
     * new element row linked to the original via `resentFromId`.
     * Bypasses the dedup gate — the admin's "Resend" click is an
     * explicit override of the dedup-prevents-spam logic.
     *
     * Skips rows whose `notificationType` doesn't map to the editable-
     * templates surface (e.g. `admin_alert_*` rows, `new_device`):
     * those are mailer-key sources rather than DB-template sources,
     * and re-rendering them requires the original event payload which
     * we don't snapshot. Callers can detect this via the bool return.
     *
     * @param NotificationLogElement $original
     * @return bool true if the resend dispatched, false if the row's
     *     type isn't resendable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resend(NotificationLogElement $original): bool
    {
        if ($original->notificationType === null) {
            return false;
        }

        $templateKey = self::_templateKeyForType($original->notificationType);

        if ($templateKey === null) {
            return false;
        }

        if ($original->userId === null) {
            // Audit row outlived the user (FK SET NULL since 5.2.0)
            // — we can't re-target the original recipient by id alone.
            return false;
        }

        $user = Craft::$app->getUsers()->getUserById($original->userId);

        if ($user === null || $user->email === null) {
            return false;
        }

        // Fresh render — no snapshot replay. If the admin edited the
        // template since the original send, the resend reflects the
        // current state.
        $extraVars = match ($original->notificationType) {
            'expiry_reminder' => [
                'daysUntilExpiry' => $this->_estimateDaysUntilExpiry($user),
            ],
            'breach_detected' => [
                'detectedAt' => new DateTime('now'),
            ],
            default => [],
        };

        $this->_dispatch(
            user: $user,
            type: $original->notificationType,
            templateKey: $templateKey,
            extraVars: $extraVars,
            resentFromId: (int)$original->id,
        );

        return true;
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
     * Optionally captures the rendered subject + body strings into
     * `$rendered['subject']` and `$rendered['body']` so the dispatch
     * path can persist them on the notification log row without
     * re-running Twig (`renderString()` has potential side effects in
     * admin-edited templates — calling it twice per send is wasteful).
     *
     * @param NotificationTemplateModel $template the template to render
     * @param User $user the recipient (used as `from` for elevated session)
     * @param array<string, mixed> $vars Twig render context
     * @param array<string, string>|null $rendered out-param — populated
     *     with `subject` + `body` rendered strings when not null
     * @return \craft\mail\Message
     *
     * @throws Throwable when Twig fails to render
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function composeFromTemplate(
        NotificationTemplateModel $template,
        User $user,
        array $vars,
        ?array &$rendered = null,
    ): \craft\mail\Message {
        $view = Craft::$app->getView();

        $subject = $view->renderString($template->subject, $vars);
        $body = $view->renderString($template->body, $vars);

        if ($rendered !== null) {
            $rendered = ['subject' => $subject, 'body' => $body];
        }

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
     * Shared dispatch path for editable-template-backed notifications
     * (`expiry_reminder`, `breach_detected`). Resolves the per-user
     * site, loads the template, renders subject + body, attempts the
     * send, and writes a log row — `status = sent` on success,
     * `status = failed` with the captured error message on
     * `Throwable`.
     *
     * @param User $user
     * @param string $type machine-key matching `notification_log.notificationType`
     * @param string $templateKey notification-templates handle (e.g. `expiry-reminder`)
     * @param array<string, mixed> $extraVars vars merged into the render context (besides `user` + `siteName`)
     * @param int|null $resentFromId set when this dispatch is a re-send of an earlier row
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dispatch(
        User $user,
        string $type,
        string $templateKey,
        array $extraVars = [],
        ?int $resentFromId = null,
    ): void {
        $siteId = $this->_resolveSiteIdForUser($user);
        $template = PasswordPolicy::$plugin->getNotificationTemplates()
            ->getTemplate($templateKey, $siteId);

        if ($template === null) {
            // Missing-template is a config error, not a send failure —
            // log and return without writing a notification_log row.
            // Operator should fix the template before any further
            // sends to this user fire.
            Craft::warning(
                "No {$templateKey} template found for user {$user->id} (siteId {$siteId})",
                'password-policy',
            );
            return;
        }

        $rendered = [];

        try {
            $vars = array_merge([
                'user' => $user,
                'siteName' => Craft::$app->getSites()->getSiteById($siteId)?->getName()
                    ?? Craft::$app->getSystemName(),
            ], $extraVars);

            // Render once via composeFromTemplate's out-param. Capturing
            // the rendered strings outside the Symfony Message object
            // is what lets us persist subject + body on the log row
            // without re-running Twig (admin-edited templates may have
            // side effects; double-rendering is also pure waste).
            $message = $this->composeFromTemplate($template, $user, $vars, $rendered);

            $message->setTo($user->email)->send();
        } catch (Throwable $e) {
            // Privacy invariant on the breach-detected path: the
            // exception message can only originate from template
            // rendering or mailer transport — neither carries
            // password material — but we still log only an opaque
            // summary at error level. The detailed message goes into
            // the notification_log errorMessage column.
            Craft::error(
                "Failed to send {$type} notification to user {$user->id}: " . $e->getMessage(),
                'password-policy',
            );

            $this->_logNotification(
                userId: $user->id,
                type: $type,
                status: NotificationStatus::Failed,
                recipient: $user->email,
                siteId: $siteId,
                subject: $rendered['subject'] ?? null,
                body: $rendered['body'] ?? null,
                errorMessage: $e->getMessage(),
                resentFromId: $resentFromId,
            );

            return;
        }

        $this->_logNotification(
            userId: $user->id,
            type: $type,
            status: NotificationStatus::Sent,
            recipient: $user->email,
            siteId: $siteId,
            subject: $rendered['subject'] ?? '',
            body: $rendered['body'] ?? '',
            errorMessage: null,
            resentFromId: $resentFromId,
        );
    }

    /**
     * Dispatch + log path for `composeFromKey` notifications (mailer-
     * templates.php source). Subject + body capture is intentionally
     * skipped — the rendered content lives inside the Symfony Message
     * and isn't trivially extractable, and the operator-visibility
     * value is low because these templates aren't admin-edited. The
     * log row still records `status`, `recipientEmail`, and the
     * `errorMessage` on failure — enough for the activity index to
     * tell admins "the new-device alert went to alice@x.com on
     * 2026-05-06" or "admin-alert send failed: connection refused."
     *
     * Phase G adds `new-device-alert` + `admin-security-alert` to
     * the editable-templates surface; at that point those paths
     * move to `_dispatch()` and gain full subject + body capture.
     *
     * @param int|null $userId user-scoped row, null for admin alerts (no specific user)
     * @param string $type machine-key matching `notification_log.notificationType`
     * @param string $recipient address the message goes to
     * @param \craft\mail\Message $sender prepared mailer message
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dispatchMailerKey(
        ?int $userId,
        string $type,
        string $recipient,
        \craft\mail\Message $sender,
    ): void {
        try {
            $sender->setTo($recipient)->send();
        } catch (Throwable $e) {
            Craft::error(
                "Failed to send {$type} notification (userId {$userId}): " . $e->getMessage(),
                'password-policy',
            );

            $this->_logNotification(
                userId: $userId,
                type: $type,
                status: NotificationStatus::Failed,
                recipient: $recipient,
                siteId: null,
                subject: null,
                body: null,
                errorMessage: $e->getMessage(),
                resentFromId: null,
            );

            return;
        }

        $this->_logNotification(
            userId: $userId,
            type: $type,
            status: NotificationStatus::Sent,
            recipient: $recipient,
            siteId: null,
            subject: null,
            body: null,
            errorMessage: null,
            resentFromId: null,
        );
    }

    /**
     * Checks whether a recent fire of `$type` should suppress another
     * one for `$userId`. Returns `true` when the cooldown is still
     * active (skip), `false` when the next fire is allowed.
     *
     * Delegates to `AlertCooldownService::shouldFire()` since G7. The
     * notification-log row remains the operator-readable activity
     * trail, but the dedup decision now lives in
     * `passwordpolicy_alert_cooldowns` — two storage surfaces:
     * `notification_log` for "what was sent", `alert_cooldowns` for
     * "when alerting fired regardless of whether an email was emitted".
     *
     * Semantic flip: `AlertCooldownService::shouldFire()` returns
     * `true` when the alert MAY fire (cooldown clear). This method
     * returns `true` when the alert should be SKIPPED (cooldown
     * active). The `!` is intentional — see the inline comment below.
     *
     * Window unit: F2 stored the window in days
     * (`expiryReminderDays`); the cooldown service takes seconds.
     * Multiply by 86400 at the boundary.
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
        $window = $settings->expiryReminderDays * 86400;

        // Semantic flip: shouldFire() returns true when ok-to-fire
        // (cooldown clear). _hasRecentNotification() returns true when
        // the caller should SKIP the fire (recent notification suppresses
        // it). The `!` translates "ok-to-fire" → "skip-fire". Future
        // maintainers: do NOT remove the `!` thinking the polarity is
        // wrong — the polarity is intentional.
        return !PasswordPolicy::$plugin->getAlertCooldown()->shouldFire(
            $type,
            "user:{$userId}",
            $window,
        );
    }

    /**
     * Saves a notification log element. Wrapped in try/catch so a
     * save failure on the failure path doesn't double-fault the
     * caller — the worst case is operators don't see the failure on
     * the activity index.
     *
     * Routes through `Craft::$app->getElements()->saveElement()` so
     * the paired `craft_elements` row is allocated first; the
     * element's `afterSave()` persists the record. Element id IS
     * record id IS `craft_elements.id`.
     *
     * `userId` is passed as int|null since 5.2.0: the audit row
     * outlives the user (`SET NULL` on user hard-delete). Admin-alert
     * paths still use `userId = null` to indicate "no specific user."
     *
     * @param int|null $userId null for admin alerts (no specific user)
     * @param string $type
     * @param NotificationStatus $status
     * @param string|null $recipient
     * @param int|null $siteId
     * @param string|null $subject
     * @param string|null $body
     * @param string|null $errorMessage
     * @param int|null $resentFromId
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _logNotification(
        ?int $userId,
        string $type,
        NotificationStatus $status,
        ?string $recipient,
        ?int $siteId,
        ?string $subject,
        ?string $body,
        ?string $errorMessage,
        ?int $resentFromId,
    ): void {
        try {
            $element = new NotificationLogElement();
            $element->userId = $userId;
            $element->notificationType = $type;
            $element->status = $status->value;
            $element->recipientEmail = $recipient;
            $element->siteIdValue = $siteId;
            $element->subject = $subject;
            $element->body = $body;
            $element->errorMessage = $errorMessage;
            $element->resentFromId = $resentFromId;
            $element->sentAt = DateTimeHelper::toDateTime(Carbon::now('UTC')->format('Y-m-d H:i:s')) ?: new DateTime('now');

            Craft::$app->getElements()->saveElement($element, false);
        } catch (Throwable $e) {
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

    /**
     * Estimates `daysUntilExpiry` for a re-rendered expiry reminder.
     * Reads `users.lastPasswordChangeDate` directly (memory gap #9 —
     * UserQuery doesn't select it) and subtracts from the configured
     * expiry interval. Falls back to 0 when expiry isn't configured
     * or the user has no recorded change — the resend admin can still
     * fire the email; the operator-facing message stays sensible.
     *
     * @param User $user
     * @return int days remaining (clamped at zero from below)
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _estimateDaysUntilExpiry(User $user): int
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return 0;
        }

        $lastChangeRaw = (new Query())
            ->select(['lastPasswordChangeDate'])
            ->from(\craft\db\Table::USERS)
            ->where(['id' => $user->id])
            ->scalar();

        if (!is_string($lastChangeRaw) || $lastChangeRaw === '') {
            return 0;
        }

        try {
            $lastChange = new DateTime($lastChangeRaw);
        } catch (Throwable) {
            return 0;
        }

        $spec = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };

        if ($spec === null) {
            return 0;
        }

        try {
            $expiresAt = (clone $lastChange)->add(new \DateInterval($spec));
        } catch (Throwable) {
            return 0;
        }

        $diff = (new DateTime('now'))->diff($expiresAt);

        if ($diff->invert) {
            return 0;
        }

        return (int)$diff->days;
    }

    // Static Methods
    // =========================================================================

    /**
     * Returns the editable-templates handle for a given
     * `notificationType` machine-key, or null when the type isn't
     * resendable. Currently only the editable-template-driven types
     * (`expiry_reminder`, `breach_detected`) are resendable; mailer-
     * key-driven types (`new_device`, `admin_alert_*`) need the
     * original event payload to re-render and aren't snapshotted.
     *
     * @param string $type
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _templateKeyForType(string $type): ?string
    {
        return match ($type) {
            'expiry_reminder' => 'expiry-reminder',
            'breach_detected' => 'breach-detected',
            default => null,
        };
    }
}
