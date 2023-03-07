<?php

namespace percipiolondon\passwordpolicy\jobs;

use Craft;
use craft\queue\BaseJob;
use percipiolondon\passwordpolicy\PasswordPolicy;

class ForcePasswordResetJob extends BaseJob
{
    public $criteria;

    public function execute($queue): void
    {
        $now = new \DateTime();

        if (
            is_null($this->criteria['user']->lastPasswordChangeDate) ||
            (
                $this->criteria['user']->lastPasswordChangeDate &&
                $this->criteria['user']->lastPasswordChangeDate->diff($now)->days > PasswordPolicy::getInstance()->getSettings()->forcePasswordResetDays
            )
        ) {
            $this->criteria['user']->passwordResetRequired = true;
            Craft::$app->getElements()->saveElement($this->criteria['user']);
        }
    }
}