<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use Craft;
use craft\base\Model;
use craft\behaviors\EnvAttributeParserBehavior;

/**
 * Class SettingsModel
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class SettingsModel extends Model
{
    /**
     * @var int the minimum length for the password, can't be lower than 6 (Craft Standard)
     */
    public int $minLength = 6;

    /**
     * @var int the maximum length for the password, it's advised against setting a max length, but could help in cases where users know generated passwords always have a specific length.
     */
    public int $maxLength = 0;

    /**
     * @var bool if the password should contain different cases when chosen
     */
    public bool $cases = false;

    /**
     * @var bool if the password should contain at least 1 number
     */
    public bool $numbers = false;

    /**
     * @var bool if the password should require special characters
     */
    public bool $symbols = false;

    /**
     * @var bool if the password strength indicator should be shown
     */
    public bool $showStrengthIndicator = false;

    /**
     * @var bool if we should check against the "i have been pwned" database
     */
    public bool $pwned = false;

    /**
     * @var bool if we should show and enable the retention utilities
     */
    public bool $retentionUtilities = false;

    /**
     * @var int|null the expiry amount for the password retention reset period
     */
    public ?int $expiryAmount = null;

    /**
     * @var string the selected retention period value
     */
    public string $expiryPeriod = 'day';

    /**
     * @return array[]
     */

    protected function defineBehaviors(): array
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => ['minLength', 'maxLength'],
            ],
        ];
    }

    /**
     * @inheritdoc
     */
    protected function defineRules(): array
    {
        return [
            [['minLength'], 'required'],
            [
                ['minLength'],
                'number',
                'integerOnly' => true,
                'min' => 6,
                'message' => Craft::t('password-policy', 'The minimum length can not be less than 6.'),
            ],
            [
                ['maxLength'],
                'number',
                'integerOnly' => true,
                'min' => 6,
                'message' => Craft::t('password-policy', 'The minimum length can not be less than 6.'),
                'when' => function($setting) {
                    return $setting->maxLength > 0;
                },
            ],
            [
                ['maxLength'],
                'compare',
                'compareAttribute' => 'minLength',
                'operator' => '>=',
                'message' => Craft::t('password-policy', 'The minimum length must be less than or equal to the maximum length.'),
                'when' => function($setting) {
                    return $setting->maxLength > 0;
                },
            ],
            [
                ['expiryPeriod'], // Replace with the name of your dropdown/select field
                'in',
                'range' => ['day', 'week', 'month', 'year'], // Define acceptable values
                'message' => Craft::t('password-policy', 'The selected expiry period is invalid.'),
            ],
            [['cases', 'numbers', 'symbols', 'retentionUtilities'], 'boolean'],
        ];
    }
}
