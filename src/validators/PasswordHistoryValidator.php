<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
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
 * Class PasswordHistoryValidator
 *
 * Validates that a password has not been previously used by the same user.
 * Gated on Pro edition and passwordHistoryCount > 0.
 *
 * Note: The User model is available via $model in validateAttribute() —
 * Yii passes the model being validated, so this works without a signature
 * change to defineRules().
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordHistoryValidator extends Validator
{
    // Public Properties
    // =========================================================================

    /**
     * @var bool
     */
    public $skipOnError = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateAttribute($model, $attribute): void
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();

        // Gate: history feature enabled (count > 0). Available on every
        // edition since 5.2.0 — per-group history merge stays Pro via
        // `PolicyResolverService`, but the global setting applies to
        // every edition.
        if ($settings->passwordHistoryCount <= 0) {
            return;
        }

        $password = $model->$attribute;
        if (empty($password)) {
            return;
        }

        // Only check for existing users (new users have no history)
        if (!$model instanceof User || !$model->id) {
            return;
        }

        if ($plugin->getPasswordHistory()->isPasswordReused($model->id, $password)) {
            $this->addError(
                $model,
                $attribute,
                Craft::t(
                    'password-policy',
                    'This password has been used recently. Please choose a different password.',
                ),
            );
        }
    }
}
