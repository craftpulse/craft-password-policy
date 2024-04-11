<?php
/**
 * Password Policy plugin for Craft CMS 5.x.
 *
 * Enforce stronger passwords on your users.
 *
 * @link      https://craftpulse.com
 *
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use Craft;
use craft\base\Model;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * PasswordPolicy Settings Model.
 *
 * This is a model used to define the plugin's settings.
 *
 * Models are containers for data. Just about every time information is passed
 * between services, controllers, and templates in Craft, it’s passed via a model.
 *
 * https://craftcms.com/docs/plugins/models
 *
 * @author    CraftPulse
 *
 * @since     1.0.0
 */
class Settings extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * Require a minimum length.
     *
     * @var int
     */
    public int $minLength = 6;

    /**
     * Require a maximum length.
     *
     * @var int
     */
    public int $maxLength = 160;

    /**
     * Require different cases in the password.
     *
     * @var bool
     */
    public bool $cases = false;

    /**
     * Require numbers in the password.
     *
     * @var bool
     */
    public bool $numbers = false;

    /**
     * Require symbols in the password.
     *
     * @var bool
     */
    public bool $symbols = false;

    /**
     * Show a strength indicator.
     *
     * @var bool
     */
    public bool $showStrengthIndicator = true;

    // Public Methods
    // =========================================================================

    /**
     * Returns the validation rules for attributes.
     *
     * Validation rules are used by [[validate()]] to check if attribute values are valid.
     * Child classes may override this method to declare different validation rules.
     *
     * More info: http://www.yiiframework.com/doc-2.0/guide-input-validation.html
     *
     * @return array
     */
    public function rules(): array
    {
        return [
            [['minLength', 'maxLength'], 'integer'],
            [['cases', 'numbers', 'symbols', 'showStrengthIndicator'], 'boolean'],
        ];
    }
}
