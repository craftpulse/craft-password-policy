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
use craft\helpers\Queue;
use craftpulse\passwordpolicy\jobs\SiemForwardJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;

/**
 * Enqueues the SIEM forward sweep for pending audit-log rows.
 *
 * Forwarding runs as a batched queue job, and the plugin never enqueues
 * that job implicitly. Wiring `password-policy/siem/run` to cron is the
 * supported production setup, exactly as it is for `gc/run`: without the
 * cron, audit rows keep `forwardedAt` empty and nothing reaches the SIEM.
 *
 * A five-minute cadence suits most installs. The Cron setup page in the
 * plugin docs carries ready-made crontab, Forge, and Kubernetes entries.
 *
 * Requires the Enterprise edition. On a lower edition the command writes
 * to stderr and returns a non-zero exit code WITHOUT throwing, per the
 * console edition-gate convention, so a cron wrapper sees a clean
 * failure instead of a stack trace.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SiemController extends Controller
{
    // Public Methods
    // =========================================================================

    /**
     * Enqueues the batched job that forwards pending audit rows to every active SIEM forwarder.
     *
     * The job walks `passwordpolicy_audit_log` by watermark, forwarding
     * rows whose `forwardedAt` is still empty and stamping each one as it
     * is accepted, so re-running the command after a partial pass resumes
     * rather than duplicates.
     *
     * Nothing is enqueued when no forwarder is currently active: a
     * disabled forwarder, or one inside its circuit-breaker cooldown,
     * would give the job no destination, and a cron running every few
     * minutes would otherwise fill the queue table with no-op jobs. That
     * case still exits zero, because "nothing configured yet" is not an
     * operator-actionable failure.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionRun(): int
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            $this->stderr("SIEM forwarding requires the Enterprise edition.\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $forwarderCount = count(PasswordPolicy::$plugin->getSiem()->getActiveForwarders());

        if ($forwarderCount === 0) {
            $this->stdout("No active SIEM forwarders. Nothing enqueued.\n");

            return ExitCode::OK;
        }

        Queue::push(new SiemForwardJob());

        $this->stdout("SIEM forward sweep enqueued for {$forwarderCount} active forwarder(s).\n");
        PasswordPolicy::$plugin->log('SIEM forward sweep queued [forwarders={forwarders}]', [
            'forwarders' => $forwarderCount,
        ]);

        return ExitCode::OK;
    }
}
