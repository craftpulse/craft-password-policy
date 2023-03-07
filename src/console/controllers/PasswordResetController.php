<?php

namespace percipiolondon\passwordpolicy\console\controllers;

use craft\console\Controller;
use craft\elements\User;
use craft\helpers\Queue;
use percipiolondon\passwordpolicy\jobs\ForcePasswordResetJob;
use percipiolondon\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;

class PasswordResetController extends Controller
{
    public function actionDefault(): int
    {
        $users = User::find()->addSelect('lastPasswordChangeDate')->all();

        if (PasswordPolicy::getInstance()->getSettings()->forcePasswordReset) {
            foreach($users as $user) {
                Queue::push(new ForcePasswordResetJob([
                    'criteria' => [
                        'user' => $user
                    ],
                    'description' => 'Force password check for '. $user->email
                ]));
            }
        }

        return ExitCode::OK;
    }
}