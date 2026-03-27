<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\validators;

use Craft;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\validators\Validator;

/**
 * Class PasswordReuseValidator
 *
 * Validates that a user is not reusing a recently used password.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordReuseValidator extends Validator
{
    /**
     * @inheritdoc
     */
    public function validateAttribute($model, $attribute): void
    {
        /** @var User $model */
        $userId = $model->id;
        $password = $model->$attribute;

        // Skip check for new users (no ID yet) or empty values
        if (!$userId || !$password) {
            return;
        }

        $count = PasswordPolicy::$plugin->settings->preventPasswordReuseCount;

        if (PasswordPolicy::$plugin->passwordHistory->hasPasswordBeenUsed($userId, $password, $count)) {
            $this->addError(
                $model,
                $attribute,
                Craft::t(
                    'password-policy',
                    'You cannot reuse one of your last {count, number} {count, plural, =1{{password}} other{passwords}}.',
                    ['count' => $count]
                )
            );
        }
    }
}
