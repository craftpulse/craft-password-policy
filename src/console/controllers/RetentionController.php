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
use craftpulse\passwordpolicy\PasswordPolicy;

use yii\console\Controller;
use yii\console\ExitCode;
use yii\helpers\BaseConsole;

/**
 * Class RetentionController
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
*/
class RetentionController extends Controller
{
    /**
     * @var bool Whether jobs should be only queued and not run.
     */
    public bool $queue = false;

    /**
     * @var bool Whether verbose output should be enabled
     */
    public bool $verbose = false;

    /**
     * @inheritdoc
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
     */
    public function getHelp(): string
    {
        return 'Password retention actions.';
    }

    /**
     * @inheritdoc
     */
    public function getHelpSummary(): string
    {
        return $this->getHelp();
    }

    /**
     * Force resets all passwords
     * @return int
     */
    public function actionForceResetPasswords(): int
    {
        if (!PasswordPolicy::$plugin->settings->retentionUtilities) {
            $this->stderr(Craft::t('password-policy', 'Password retention features are disabled.') . PHP_EOL, BaseConsole::FG_RED);

            return ExitCode::OK;
        }

        $this->forceResetPasswords();

        return ExitCode::OK;
    }

    /**
     * @param string $message
     * @return void
     */
    private function output(string $message): void
    {
        $this->stdout(Craft::t('password-policy', $message) . PHP_EOL, BaseConsole::FG_GREEN);
    }

    /**
     * @param $users array
     * @return void
     */
    private function forceResetPasswords(): void
    {
        if ($this->queue) {
            PasswordPolicy::$plugin->retention->resetPasswords();
            $this->output('Users queued for password resets.');

            return;
        }

        $this->stdout(Craft::t('password-policy', 'Resetting passwords...') . PHP_EOL, BaseConsole::FG_GREEN);
        PasswordPolicy::$plugin->retention->resetPasswords();
        $this->output('Password resets complete.');
    }
}
