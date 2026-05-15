<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\console\controllers;

use craft\console\Controller;
use craft\helpers\Queue;
use craftpulse\passwordpolicy\jobs\SendPasswordExpiryRemindersJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;

/**
 * Class NotificationController
 *
 * Console commands for queueing notification work. Pro-only — Lite exits
 * non-zero with a stderr message rather than no-op'ing silently.
 *
 * `gc/run` already handles notification log retention, so this controller
 * has no `actionPrune`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var int|null target a single user ID instead of every expiring user
     */
    public ?int $user = null;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function options($actionID): array
    {
        $options = parent::options($actionID);

        if ($actionID === 'send-expiry-reminders') {
            $options[] = 'user';
        }

        return $options;
    }

    /**
     * Enqueues a single batched job that sends password-expiry reminders
     * to every eligible user (or just the user passed via `--user=<id>`).
     *
     * The job recomputes its recipient set per batch via the batcher's
     * `getSlice()` so retries are naturally idempotent — already-notified
     * users drop out via the dedup subquery.
     *
     * Universal across editions since 5.2.0. Lite operators can wire
     * this command to cron and get the seeded default template
     * rendered; Pro operators get whatever their Notification
     * Templates editor wrote.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSendExpiryReminders(): int
    {
        Queue::push(new SendPasswordExpiryRemindersJob([
            'userId' => $this->user,
        ]));

        $message = $this->user !== null
            ? "Password expiry reminder enqueued for user {$this->user}.\n"
            : "Password expiry reminders enqueued.\n";

        $this->stdout($message);
        PasswordPolicy::$plugin->log('Password expiry reminders queued [{userId}]', [
            'userId' => $this->user ?? 'all',
        ]);

        return ExitCode::OK;
    }
}
