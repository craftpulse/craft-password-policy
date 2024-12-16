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

use Craft;
use craft\base\Component;
use craft\elements\User as UserElement;
use craft\helpers\Queue;

use craftpulse\passwordpolicy\jobs\PasswordResetJob;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class RetentionService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class RetentionService extends Component
{
    /**
     * @var int
     */
    public int $resets = 0;

    /**
     * @inheritdoc
     */
    public function resetPasswords(): void
    {
        // @TODO create job priority setting
        // @TODO create job ttr setting
        Queue::push(
            job: new PasswordResetJob([
                'description' => Craft::t('password-policy', 'Resetting passwords'),
            ]),
            priority: 10,
            ttr: 300,
            queue: PasswordPolicy::$plugin->queue,
        );
    }

    public function requirePasswordReset(UserElement $user): void
    {
        // In the free version we will never force the reset of our main admin account!
        if ($user->id !== 1) {
            $user->passwordResetRequired = true;
            Craft::$app->getElements()->saveElement($user);
            $this->resets++;
        }
    }
}
