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
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;

/**
 * Class GcController
 *
 * Deterministic garbage collection for all plugin tables. For guaranteed
 * retention compliance, schedule this command via cron rather than relying
 * on Craft's probabilistic GC (1 in 100,000 requests).
 *
 * Recommended crontab entry (daily at 2am):
 * `0 2 * * * /usr/bin/env php /path/to/craft password-policy/gc/run`
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GcController extends Controller
{
    // Public Methods
    // =========================================================================

    /**
     * Runs garbage collection on all plugin tables.
     *
     * Purges expired data from: password history (respecting count floor),
     * audit log, notification log. Each table respects its configured
     * retention period.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionRun(): int
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();

        $this->stdout("Password Policy — Garbage Collection\n");
        $this->stdout(str_repeat('-', 40) . "\n");

        // Password history (Pro)
        if ($plugin->getIsPro() && $settings->passwordHistoryCount > 0) {
            $purged = $plugin->getPasswordHistory()->purgeExpiredHistory(
                $settings->passwordHistoryExpiryDays,
                $settings->passwordHistoryCount,
            );
            $this->stdout("Password history: {$purged} expired entries purged (count floor: {$settings->passwordHistoryCount}, TTL: {$settings->passwordHistoryExpiryDays} days)\n");
        } else {
            $this->stdout("Password history: skipped (disabled or Lite edition)\n");
        }

        // Notification log (Pro+)
        if ($plugin->getIsPro()) {
            $purged = $plugin->getNotification()->pruneOldEntries(
                $settings->notificationLogRetentionDays,
            );
            $this->stdout("Notification log: {$purged} entries purged (TTL: {$settings->notificationLogRetentionDays} days)\n");
        } else {
            $this->stdout("Notification log: skipped (Lite edition)\n");
        }

        // Audit log (Enterprise)
        if ($plugin->getIsEnterprise() && $settings->enableAuditLog) {
            $purged = $plugin->getAuditLog()->purgeOldEntries(
                $settings->auditLogRetentionDays,
            );
            $this->stdout("Audit log: {$purged} entries purged (TTL: {$settings->auditLogRetentionDays} days)\n");
        } else {
            $this->stdout("Audit log: skipped (disabled or not Enterprise)\n");
        }

        $this->stdout(str_repeat('-', 40) . "\n");
        $this->stdout("Done.\n");

        return ExitCode::OK;
    }
}
