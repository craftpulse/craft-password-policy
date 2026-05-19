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
use craft\web\View;
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
 * **Single dispatch path.** All four notification keys route through
 * `_dispatch()` and the per-(key, site) editable-templates surface.
 * Pre-G12, `new-device-alert` and `admin-security-alert` used
 * `Craft::$app->getMailer()->composeFromKey()` against mailer-template
 * keys that were never registered with `SystemMessages::EVENT_REGISTER_
 * MESSAGES`, so those emails failed to render. G12 moved both keys
 * onto the editable surface with default content from `EmailDefaults`,
 * a seed migration for upgraders, and full subject/body capture on the
 * log row.
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
 * Capture is non-negotiable across editions — Lite installs write
 * `notification_log` rows for the dispatch surfaces they have
 * (expiry reminders — universal since 5.2.0). Pro adds breach-detected
 * and new-device alerts; Enterprise adds admin security alerts via
 * `adminAlertEmail`. The activity-surface CP screen is gated to Pro+
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
     * Universal across editions since 5.2.0. Lite installs render the
     * seeded `expiry-reminder` template (read-only on Lite — the
     * Notification Templates editor UI remains a Pro feature). Pro
     * editors can override the template content per site; Enterprise
     * gets activity-log + resend on top.
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
     * Routes through the editable-templates surface since G12 — the
     * pre-G12 `composeFromKey('password-policy:new-device-alert', ...)`
     * path never had a corresponding `SystemMessages` registration, so
     * the email rendered empty. Defaults live in
     * `EmailDefaults::newDeviceAlert()` and seed per-site rows via
     * `Install::_seedNotificationTemplateDefaults()` (fresh installs) or
     * `m260513_185354_AddEnterpriseNotificationDefaults` (upgraders).
     *
     * Note on resend: `new_device` log rows are still NOT resendable —
     * the input vars (`deviceLabel`, `maskedIp`) aren't snapshotted on
     * the log row, and `_templateKeyForType()` continues to return null
     * for this type. A future `templateVarsJson` column would unlock
     * resend (additive future work, not part of G12).
     *
     * Pro-only. The HIBP-on-login listener that drives this method
     * only registers on Pro, but the guard duplicates here as
     * defense-in-depth — matches the `sendPasswordExpiryReminder()` /
     * `sendBreachDetected()` shape (P1-NotifPro).
     *
     * @param User $user
     * @param string $deviceLabel
     * @param string $maskedIp
     * @return void
     *
     * @throws RuntimeException when the plugin is running the Lite edition
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendNewDeviceAlert(User $user, string $deviceLabel, string $maskedIp): void
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new RuntimeException('New-device alerts require the Pro edition.');
        }

        if ($user->email === null) {
            return;
        }

        $this->_dispatch(
            user: $user,
            type: 'new_device',
            templateKey: 'new-device-alert',
            extraVars: [
                'deviceLabel' => $deviceLabel,
                'maskedIp' => $maskedIp,
            ],
        );
    }

    /**
     * Sends an admin security alert.
     *
     * Routes through the editable-templates surface since G12 — the
     * pre-G12 `composeFromKey('password-policy:admin-security-alert', ...)`
     * path never had a corresponding `SystemMessages` registration, so
     * the email rendered empty. Defaults live in
     * `EmailDefaults::adminSecurityAlert()` and seed per-site rows via
     * `Install::_seedNotificationTemplateDefaults()` (fresh installs) or
     * `m260513_185354_AddEnterpriseNotificationDefaults` (upgraders).
     *
     * Recipient is the configured `adminAlertEmail` (operator inbox),
     * not the end-user — `_dispatch()` receives `user: null` and
     * `recipientOverride: $email`, and the rendered template omits any
     * `{{ user.* }}` reference. Site context resolves to the primary
     * site (admin alerts aren't user-scoped).
     *
     * Cooldown gate (`AlertCooldownService`) is preserved from pre-G12 —
     * one alert per (event, cooldownKey) per window, recorded on the
     * dispatch attempt regardless of outcome.
     *
     * @param string $event
     * @param array<string, mixed> $context
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

        $this->_dispatch(
            user: null,
            type: 'admin_alert_' . $event,
            templateKey: 'admin-security-alert',
            extraVars: [
                'event' => $event,
                'context' => $context,
            ],
            recipientOverride: $email,
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
     * Skips rows whose `notificationType` doesn't snapshot the input
     * variables needed to re-render (`new_device` needs `deviceLabel`
     * + `maskedIp`; `admin_alert_*` needs the event-specific `context`
     * payload). Since G12 every key renders against the editable-
     * templates surface, but only the user-driven keys
     * (`expiry_reminder`, `breach_detected`) recompute their input
     * vars from current state — the others would need a
     * `templateVarsJson` snapshot column to be resendable (additive
     * future work, not part of G12). Callers detect this via the bool
     * return.
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
     * **G11 — Enterprise custom template paths.** When the template has a
     * non-empty `$templatePath` AND the plugin is running the Enterprise
     * edition, the body renders from a site Twig file
     * (`View::TEMPLATE_MODE_SITE`) instead of the DB-stored `$body`
     * field. Subject ALWAYS renders from the DB `$subject` field — admins
     * want to edit subject without touching a Twig file. The Enterprise
     * gate lives at the renderer (not at field load) so a downgrade from
     * Enterprise to Pro silently falls back to the DB body without
     * rewriting any rows. Missing-template errors propagate naturally —
     * `renderTemplate()` throws and the dispatch path's catch block
     * captures `status = failed` with the Twig exception message.
     *
     * @param NotificationTemplateModel $template the template to render
     * @param User|null $user the recipient when the template is user-scoped;
     *     null for admin-recipient templates (G12 — `admin-security-alert`).
     *     The `$user` reference is retained on the signature for caller
     *     readability and forward compatibility (e.g. an elevated-session
     *     `from` field tied to the user-side mail flow); the method body
     *     does not currently read it.
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
        ?User $user,
        array $vars,
        ?array &$rendered = null,
    ): \craft\mail\Message {
        $view = Craft::$app->getView();
        $plugin = PasswordPolicy::$plugin;

        $useTemplateFile = $template->templatePath !== null
            && $template->templatePath !== ''
            && $plugin->getIsEnterprise();

        $subject = $view->renderString($template->subject, $vars);
        $body = $useTemplateFile
            ? $view->renderTemplate($template->templatePath, $vars, View::TEMPLATE_MODE_SITE)
            : $view->renderString($template->body, $vars);

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
     * Shared dispatch path for editable-template-backed notifications.
     * Resolves the target site, loads the template, renders subject +
     * body, attempts the send, and writes a log row — `status = sent`
     * on success, `status = failed` with the captured error message on
     * `Throwable`.
     *
     * Supports two modes:
     *
     *  - **User-scoped** (`$user !== null`, `$recipientOverride === null`):
     *    site resolves from the user's `preferredLanguage`; recipient is
     *    the user's email; the render context includes `{{ user }}`.
     *    Used by `expiry_reminder`, `breach_detected`, `new_device`.
     *  - **Admin-scoped** (`$user === null`, `$recipientOverride !== null`):
     *    site resolves to the primary site (or `$siteIdOverride` when
     *    explicitly passed); recipient is `$recipientOverride`; the
     *    render context omits `{{ user }}` and `userId` writes as null
     *    on the log row. Used by `admin_alert_*`.
     *
     * Missing template is a config error — log a warning and return
     * without writing a log row. Send/render failures DO write a
     * `status = failed` row so operators see the failure on the
     * activity index.
     *
     * @param User|null $user the recipient user, or null for admin-scoped sends
     * @param string $type machine-key matching `notification_log.notificationType`
     * @param string $templateKey notification-templates handle (e.g. `expiry-reminder`)
     * @param array<string, mixed> $extraVars vars merged into the render context (besides `user` + `siteName`)
     * @param string|null $recipientOverride explicit recipient email for admin-scoped sends
     * @param int|null $siteIdOverride explicit site ID for admin-scoped sends; defaults to primary site
     * @param int|null $resentFromId set when this dispatch is a re-send of an earlier row
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _dispatch(
        ?User $user,
        string $type,
        string $templateKey,
        array $extraVars = [],
        ?string $recipientOverride = null,
        ?int $siteIdOverride = null,
        ?int $resentFromId = null,
    ): void {
        $siteId = $siteIdOverride
            ?? ($user !== null
                ? $this->_resolveSiteIdForUser($user)
                : Craft::$app->getSites()->getPrimarySite()->id);

        $recipient = $recipientOverride ?? $user?->email;

        if ($recipient === null) {
            // Nothing to send to — caller is responsible for filtering
            // (User::email===null + no override). Defensive return so
            // a misuse doesn't write a log row with a null recipient.
            return;
        }

        $userId = $user?->id;

        $template = PasswordPolicy::$plugin->getNotificationTemplates()
            ->getTemplate($templateKey, $siteId);

        if ($template === null) {
            // Missing-template is a config error, not a send failure —
            // log and return without writing a notification_log row.
            // Operator should fix the template before any further
            // sends fire.
            $userContext = $userId !== null ? "user {$userId}" : "admin-scoped";
            Craft::warning(
                "No {$templateKey} template found for {$userContext} (siteId {$siteId})",
                'password-policy',
            );
            return;
        }

        $rendered = [];

        try {
            $baseVars = [
                'siteName' => Craft::$app->getSites()->getSiteById($siteId)?->getName()
                    ?? Craft::$app->getSystemName(),
            ];

            if ($user !== null) {
                $baseVars['user'] = $user;
            }

            $vars = array_merge($baseVars, $extraVars);

            // Render once via composeFromTemplate's out-param. Capturing
            // the rendered strings outside the Symfony Message object
            // is what lets us persist subject + body on the log row
            // without re-running Twig (admin-edited templates may have
            // side effects; double-rendering is also pure waste).
            $message = $this->composeFromTemplate($template, $user, $vars, $rendered);

            $message->setTo($recipient)->send();
        } catch (Throwable $e) {
            // Privacy invariant on the breach-detected path: the
            // exception message can only originate from template
            // rendering or mailer transport — neither carries
            // password material — but we still log only an opaque
            // summary at error level. The detailed message goes into
            // the notification_log errorMessage column.
            $userContext = $userId !== null ? "user {$userId}" : "admin-scoped";
            Craft::error(
                "Failed to send {$type} notification to {$userContext}: " . $e->getMessage(),
                'password-policy',
            );

            $this->_logNotification(
                userId: $userId,
                type: $type,
                status: NotificationStatus::Failed,
                recipient: $recipient,
                siteId: $siteId,
                subject: $rendered['subject'] ?? null,
                body: $rendered['body'] ?? null,
                errorMessage: $e->getMessage(),
                resentFromId: $resentFromId,
            );

            return;
        }

        $this->_logNotification(
            userId: $userId,
            type: $type,
            status: NotificationStatus::Sent,
            recipient: $recipient,
            siteId: $siteId,
            subject: $rendered['subject'] ?? '',
            body: $rendered['body'] ?? '',
            errorMessage: null,
            resentFromId: $resentFromId,
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
     * resendable.
     *
     * Since G12 every key in this service renders against the
     * editable-templates surface (handles `expiry-reminder`,
     * `breach-detected`, `new-device-alert`, `admin-security-alert`).
     * Resendability is a separate axis: only the types whose input
     * vars can be recomputed from current state qualify
     * (`expiry_reminder` recomputes `daysUntilExpiry` from
     * `users.lastPasswordChangeDate`; `breach_detected` reuses
     * `detectedAt = now`). The remaining types — `new_device` and
     * every `admin_alert_*` — depend on inputs that aren't snapshotted
     * on the log row (`deviceLabel`, `maskedIp`, the event `context`
     * payload), so they return null here and `resend()` short-circuits.
     *
     * Forward-pointer: a `templateVarsJson` snapshot column on the log
     * row would unlock resend for the other types (additive enhancement
     * — no schema rewrites, no data migration — appropriate for 5.3+).
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
