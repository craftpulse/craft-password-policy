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
use craftpulse\passwordpolicy\enums\InactiveAction;
use craftpulse\passwordpolicy\jobs\ScanInactiveAccountsJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;

/**
 * Class InactiveController
 *
 * Console command for the Feature 5 (Pro) inactive-account scan. Enqueues a
 * single batched job that flags / notifies / suspends accounts past the
 * inactivity threshold according to the configured `inactiveAction`.
 *
 * The scan is OPERATOR-SCHEDULED, not automatic. Wiring
 * `password-policy/inactive/scan` to cron is the recommended production
 * setup (see `feedback_retention_gc_framing`). The plugin never runs it
 * implicitly.
 *
 * Edition gate (console convention → graceful skip, per
 * `feedback_edition_gate_convention`): on a sub-Pro install the command
 * writes to stderr and returns `ExitCode::UNSPECIFIED_ERROR` WITHOUT
 * throwing, because a throw would crash the command rather than surface a
 * clean non-zero exit a cron wrapper can act on.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class InactiveController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var int|null override the configured `inactiveThresholdDays`
     */
    public ?int $threshold = null;

    /**
     * @var string|null override the configured `inactiveAction`
     * (`report` | `notify` | `suspend`). Exposed as the `--mode` flag
     * rather than `--action` because `action` collides with the base
     * `yii\base\Controller::$action` property.
     */
    public ?string $mode = null;

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

        if ($actionID === 'scan') {
            $options[] = 'threshold';
            $options[] = 'mode';
        }

        return $options;
    }

    /**
     * Enqueues the inactive-account scan job.
     *
     * Refuses to enqueue on a sub-Pro install or when the feature is
     * disabled, so operators get an immediate, clear non-zero exit rather
     * than a silently-dropped job. The `--threshold` / `--mode` flags
     * override the configured settings for one-off runs (e.g. a dry-run
     * with `--mode=report` against a low threshold before flipping to
     * suspend).
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionScan(): int
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            $this->stderr("Inactive-account handling requires the Pro edition.\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        if (!PasswordPolicy::$plugin->getSettings()->inactiveAccountsEnabled) {
            $this->stderr("Inactive-account handling is disabled. Enable it in the plugin settings first.\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        if ($this->mode !== null && InactiveAction::tryFrom($this->mode) === null) {
            $this->stderr("Invalid --mode: must be one of report, notify, suspend.\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        Queue::push(new ScanInactiveAccountsJob([
            'thresholdDays' => $this->threshold,
            'action' => $this->mode,
        ]));

        $this->stdout("Inactive-account scan enqueued.\n");
        PasswordPolicy::$plugin->log('Inactive-account scan queued [threshold={threshold}, mode={mode}]', [
            'threshold' => $this->threshold ?? 'default',
            'mode' => $this->mode ?? 'default',
        ]);

        return ExitCode::OK;
    }
}
