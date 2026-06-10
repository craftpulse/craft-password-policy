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
use craft\db\Query;
use craft\helpers\App;
use craft\models\UserGroup;
use craft\validators\HandleValidator;
use craftpulse\passwordpolicy\elements\PolicyElement;
use craftpulse\passwordpolicy\enums\PolicyPreset;

/**
 * Class PolicyModel
 *
 * Represents a named password policy that can be assigned to one or more
 * user groups. Override fields that are null inherit from the global settings.
 * Merge logic delegates to GroupPolicyModel for consistency.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyModel extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var int|null the policy ID
     */
    public ?int $id = null;

    /**
     * @var string the human-readable policy name
     */
    public string $name = '';

    /**
     * @var string the policy handle (unique identifier)
     */
    public string $handle = '';

    /**
     * @var string|null the preset this policy was derived from, if any
     */
    public ?string $preset = null;

    /**
     * @var int the sort order for policy precedence
     */
    public int $sortOrder = 0;

    /**
     * @var string|null the UID for project config
     */
    public ?string $uid = null;

    /**
     * @var int|string|null minimum password length (null = inherit global).
     * Accepts an env reference (e.g. `$PP_MIN_LENGTH`) — resolved via
     * {@see EnvAttributeParserBehavior} before validation.
     */
    public int|string|null $minLength = null;

    /**
     * @var int|string|null maximum password length (null = inherit global).
     * Accepts an env reference (e.g. `$PP_MAX_LENGTH`) — resolved via
     * {@see EnvAttributeParserBehavior} before validation.
     */
    public int|string|null $maxLength = null;

    /**
     * @var bool|null require mixed case (null = inherit global)
     */
    public ?bool $cases = null;

    /**
     * @var bool|null require numbers (null = inherit global)
     */
    public ?bool $numbers = null;

    /**
     * @var bool|null require symbols (null = inherit global)
     */
    public ?bool $symbols = null;

    /**
     * @var bool|null check HIBP (null = inherit global)
     */
    public ?bool $hibp = null;

    /**
     * @var string|null HIBP failure mode: 'open' or 'closed' (null = inherit global)
     */
    public ?string $hibpFailMode = null;

    /**
     * @var int|null password history count (null = inherit global)
     */
    public ?int $passwordHistoryCount = null;

    /**
     * @var int|null minimum change interval in hours (null = inherit global)
     *
     * @since 5.2.0
     */
    public ?int $minChangeIntervalHours = null;

    /**
     * @var bool|null check sequential chars (null = inherit global)
     */
    public ?bool $checkSequentialChars = null;

    /**
     * @var bool|null check repeated chars (null = inherit global)
     */
    public ?bool $checkRepeatedChars = null;

    /**
     * @var bool|null check contextual data (null = inherit global)
     */
    public ?bool $checkContextual = null;

    /**
     * @var bool|null check common passwords (null = inherit global)
     */
    public ?bool $checkCommonPasswords = null;

    /**
     * @var string|null complexity mode (null = inherit global)
     */
    public ?string $complexityMode = null;

    /**
     * @var int|null minimum character types (null = inherit global)
     */
    public ?int $minimumCharacterTypes = null;

    /**
     * @var int|null expiry amount (null = inherit global)
     */
    public ?int $expiryAmount = null;

    /**
     * @var string|null expiry period (null = inherit global)
     */
    public ?string $expiryPeriod = null;

    // Private Properties
    // =========================================================================

    /**
     * @var UserGroup[]|null cached user groups assigned to this policy
     */
    private ?array $_groups = null;

    // Static Methods
    // =========================================================================

    /**
     * Hydrates a `PolicyModel` from a saved `PolicyElement`. The
     * element carries the canonical id + raw column values; this
     * factory unwraps them onto the in-memory model shape that the
     * CP controller, resolver service, and Pest fixtures consume.
     *
     * Used by `PolicyService::getPolicyById()` /
     * `getPolicyByHandle()` / `getAllPolicies()` /
     * `getPoliciesForGroupIds()` to bridge the element layer onto
     * the legacy model surface — every read path resolves through
     * here so a single update to the conversion logic propagates
     * cleanly.
     *
     * The `settings` JSON column populated on the element via
     * `PolicyElement::init()` is already an array when this runs —
     * `setSettingsFromArray()` resets every override field to null
     * first, so partial settings payloads (e.g. legacy upgrade-path
     * rows that lost a column) cleanly land as inherits.
     *
     * @param PolicyElement $element
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromElement(PolicyElement $element): self
    {
        $model = new self();
        $model->id = (int)$element->id;
        $model->name = $element->name ?? '';
        $model->handle = $element->handle ?? '';
        $model->preset = $element->preset;
        $model->sortOrder = (int)$element->sortOrder;
        $model->uid = $element->uid;

        if (is_array($element->settings)) {
            $model->setSettingsFromArray($element->settings);
        }

        return $model;
    }

    /**
     * Returns the override fields that map to the JSON settings column.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function settingsFields(): array
    {
        return [
            'minLength',
            'maxLength',
            'cases',
            'numbers',
            'symbols',
            'hibp',
            'hibpFailMode',
            'passwordHistoryCount',
            'minChangeIntervalHours',
            'checkSequentialChars',
            'checkRepeatedChars',
            'checkContextual',
            'checkCommonPasswords',
            'complexityMode',
            'minimumCharacterTypes',
            'expiryAmount',
            'expiryPeriod',
        ];
    }

    // Public Methods
    // =========================================================================

    /**
     * Merges this policy's overrides with the global settings, returning
     * a complete SettingsModel with all fields resolved.
     *
     * Delegates to GroupPolicyModel::mergeWithGlobal() to reuse the
     * existing "most restrictive wins" merge logic. `minLength` and
     * `maxLength` may hold env references (`$PP_MIN_LENGTH` etc.) — resolve
     * via `App::parseEnv()` and cast to int before copying onto the
     * `?int`-typed GroupPolicyModel attributes.
     *
     * @param SettingsModel $global the global settings to merge against
     * @return SettingsModel the merged settings
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function mergeWithGlobal(SettingsModel $global): SettingsModel
    {
        $groupPolicy = new GroupPolicyModel();
        $envIntFields = ['minLength', 'maxLength'];

        foreach (self::settingsFields() as $field) {
            if ($this->$field === null) {
                continue;
            }

            if (in_array($field, $envIntFields, true)) {
                $groupPolicy->$field = (int)App::parseEnv((string)$this->$field);
                continue;
            }

            $groupPolicy->$field = $this->$field;
        }

        return $groupPolicy->mergeWithGlobal($global);
    }

    /**
     * Returns the user groups assigned to this policy.
     *
     * @return UserGroup[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getGroups(): array
    {
        if ($this->_groups !== null) {
            return $this->_groups;
        }

        if ($this->id === null) {
            return $this->_groups = [];
        }

        $groupIds = $this->getGroupIds();

        if (empty($groupIds)) {
            return $this->_groups = [];
        }

        $allGroups = Craft::$app->getUserGroups()->getAllGroups();
        $this->_groups = array_values(array_filter(
            $allGroups,
            fn(UserGroup $group) => in_array($group->id, $groupIds, true),
        ));

        return $this->_groups;
    }

    /**
     * Returns the IDs of user groups assigned to this policy.
     *
     * @return int[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getGroupIds(): array
    {
        if ($this->id === null) {
            return [];
        }

        return (new Query())
            ->select(['groupId'])
            ->from('{{%passwordpolicy_policy_groups}}')
            ->where(['policyId' => $this->id])
            ->column();
    }

    /**
     * Returns the names of fields that have an explicit (non-null) value
     * on this policy.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getOverrideFields(): array
    {
        $fields = [];
        foreach (self::settingsFields() as $field) {
            if ($this->$field !== null) {
                $fields[] = $field;
            }
        }
        return $fields;
    }

    /**
     * Returns the names of fields where this policy diverges from its preset.
     *
     * If no preset is set, returns all override fields (since "Custom"
     * implies every set field is intentional).
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getDivergentFields(): array
    {
        if ($this->preset === null) {
            return $this->getOverrideFields();
        }

        $presetEnum = PolicyPreset::tryFrom($this->preset);
        if ($presetEnum === null) {
            return $this->getOverrideFields();
        }

        $presetPolicy = $presetEnum->toGroupPolicy();
        $divergent = [];

        foreach (self::settingsFields() as $field) {
            if ($this->$field !== $presetPolicy->$field) {
                $divergent[] = $field;
            }
        }

        return $divergent;
    }

    /**
     * Returns only non-null override fields as an associative array
     * for JSON serialization into the settings column.
     *
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSettingsArray(): array
    {
        $settings = [];

        foreach (self::settingsFields() as $field) {
            if ($this->$field !== null) {
                $settings[$field] = $this->$field;
            }
        }

        return $settings;
    }

    /**
     * Sets override fields from an associative array.
     *
     * The array is treated as the complete set of overrides — any settings
     * field not present is reset to null (inherit). This makes it safe to
     * call after the user has cleared form fields.
     *
     * @param array<string, mixed> $settings the settings to apply
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function setSettingsFromArray(array $settings): void
    {
        // Reset every override field to null first — anything not in
        // $settings means "inherit from global"
        foreach (self::settingsFields() as $field) {
            $this->$field = null;
        }

        $validFields = array_flip(self::settingsFields());

        foreach ($settings as $key => $value) {
            if (isset($validFields[$key])) {
                $this->$key = $value;
            }
        }
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Registers the env-var parser on length attributes so `$PP_MIN_LENGTH` /
     * `$PP_MAX_LENGTH` references in the CP form are resolved before
     * validation, mirroring the global SettingsModel pattern.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defineBehaviors(): array
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => [
                    'minLength',
                    'maxLength',
                ],
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defineRules(): array
    {
        return array_merge(parent::defineRules(), [
            [['name', 'handle'], 'required'],
            [['name'], 'string', 'max' => 255],
            [
                ['handle'],
                HandleValidator::class,
                'reservedWords' => ['id', 'dateCreated', 'dateUpdated', 'uid'],
            ],
            [['maxLength'], 'validateMaxLengthAgainstMin'],
        ]);
    }

    /**
     * Inline validator: when both minLength and maxLength are set on this
     * policy, maxLength must be >= minLength. Cross-policy collisions are
     * resolved at merge time by `PolicyResolverService`; this rule only
     * guards against saving an internally inconsistent policy.
     *
     * The env-parser behavior runs in `beforeValidate`, so by the time this
     * rule fires both attributes hold resolved scalar values (or numeric
     * strings) — cast to int for the comparison so PHP's loose type juggling
     * doesn't bite us.
     *
     * @param string $attribute
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateMaxLengthAgainstMin(string $attribute): void
    {
        if ($this->minLength === null || $this->maxLength === null) {
            return;
        }

        $min = (int)$this->minLength;
        $max = (int)$this->maxLength;

        if ($max > 0 && $max < $min) {
            $this->addError($attribute, Craft::t(
                'password-policy',
                'Max length ({max}) must be greater than or equal to min length ({min}).',
                ['max' => $max, 'min' => $min],
            ));
        }
    }
}
