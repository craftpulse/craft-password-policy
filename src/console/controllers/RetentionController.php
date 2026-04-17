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

use Craft;
use craftpulse\passwordpolicy\helpers\PasswordResetHelper;
use craftpulse\passwordpolicy\PasswordPolicy;

use craftpulse\passwordpolicy\services\RetentionService;
use Throwable;
use yii\console\Controller;
use yii\console\ExitCode;
use yii\helpers\BaseConsole;

/**
 * Class RetentionController
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 *
 * @property RetentionService $retention
 */
class RetentionController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var bool Whether jobs should be pushed to the queue instead of running synchronously.
     */
    public bool $queue = false;

    /**
     * @var bool Whether verbose output should be enabled.
     */
    public bool $verbose = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function options($actionID): array
    {
        $options = parent::options($actionID);
        $options[] = 'queue';
        $options[] = 'verbose';

        return $options;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function getHelp(): string
    {
        return 'Password retention actions.';
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function getHelpSummary(): string
    {
        return $this->getHelp();
    }

    /**
     * Force resets all passwords that have expired according to the retention settings.
     *
     * @return int
     *
     * @throws Throwable
     *
     * @author CraftPulse
     */
    public function actionForceResetPasswords(): int
    {
        if (!PasswordPolicy::$plugin->getSettings()->retentionUtilities) {
            $this->stderr(Craft::t('password-policy', 'Password retention features are disabled.') . PHP_EOL, BaseConsole::FG_RED);

            return ExitCode::UNSPECIFIED_ERROR;
        }

        if ($this->queue) {
            PasswordPolicy::$plugin->retention->resetPasswords();
            $this->_output('Users queued for password resets.');

            return ExitCode::OK;
        }

        $this->stdout(Craft::t('password-policy', 'Resetting passwords...') . PHP_EOL, BaseConsole::FG_GREEN);

        $users = PasswordResetHelper::getAllUsersToExpire();

        if (empty($users)) {
            $this->_output('No users require a password reset.');

            return ExitCode::OK;
        }

        foreach ($users as $user) {
            PasswordPolicy::$plugin->retention->requirePasswordReset($user);

            if ($this->verbose) {
                $this->stdout("  Reset required for: {$user->email}" . PHP_EOL);
            }
        }

        $count = count($users);
        $this->_output("Password resets complete. {$count} user(s) flagged.");

        return ExitCode::OK;
    }

    // Private Methods
    // =========================================================================

    /**
     * Outputs a translated success message.
     *
     * @param string $message
     * @return void
     *
     * @author CraftPulse
     */
    private function _output(string $message): void
    {
        $this->stdout(Craft::t('password-policy', $message) . PHP_EOL, BaseConsole::FG_GREEN);
    }
}
