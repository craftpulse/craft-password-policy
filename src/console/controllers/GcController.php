<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
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
     * Purges expired data from: password history (respecting count
     * floor), audit log, notification log, alert cooldowns, known
     * devices, expired API tokens. Each table respects its configured
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
        $results = $plugin->runGc();

        $this->stdout("Password Policy — Garbage Collection\n");
        $this->stdout(str_repeat('-', 40) . "\n");

        if (isset($results['passwordHistory'])) {
            $this->stdout("Password history: {$results['passwordHistory']} expired entries purged (count floor: {$settings->passwordHistoryCount}, TTL: {$settings->passwordHistoryExpiryDays} days)\n");
        }
        if (isset($results['notificationLog'])) {
            $this->stdout("Notification log: {$results['notificationLog']} entries purged (TTL: {$settings->notificationLogRetentionDays} days)\n");
        }
        if (isset($results['auditLog'])) {
            $this->stdout("Audit log: {$results['auditLog']} entries purged (TTL: {$settings->auditLogRetentionDays} days)\n");
        }
        if (isset($results['alertCooldowns'])) {
            $this->stdout("Alert cooldowns: {$results['alertCooldowns']} entries purged (TTL: longest configured cooldown or 7d floor)\n");
        }
        if (isset($results['knownDevices'])) {
            $this->stdout("Known devices: {$results['knownDevices']} entries purged (TTL: {$settings->deviceRetentionDays} days)\n");
        }
        if (isset($results['apiTokens'])) {
            $this->stdout("API tokens: {$results['apiTokens']} expired tokens purged\n");
        }

        $this->stdout(str_repeat('-', 40) . "\n");
        $this->stdout("Done.\n");

        return ExitCode::OK;
    }
}
