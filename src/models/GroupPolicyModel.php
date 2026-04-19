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

use craft\base\Model;

/**
 * Class GroupPolicyModel
 *
 * Represents a per-group password policy override. Fields that are null
 * inherit from the global settings. Used with "most restrictive wins" merge.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupPolicyModel extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var string|null the preset this policy was derived from, if any
     */
    public ?string $preset = null;

    /**
     * @var int|null minimum password length (null = inherit global)
     */
    public ?int $minLength = null;

    /**
     * @var int|null maximum password length (null = inherit global)
     */
    public ?int $maxLength = null;

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
    public ?bool $pwned = null;

    /**
     * @var int|null password history count (null = inherit global)
     */
    public ?int $passwordHistoryCount = null;

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

    // Public Methods
    // =========================================================================

    /**
     * Merges this group policy with the global settings, returning
     * a complete SettingsModel with all fields resolved.
     *
     * For each field: if this group policy has a non-null value, it overrides
     * the global setting. Otherwise, the global value is used.
     *
     * @param SettingsModel $global
     * @return SettingsModel
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function mergeWithGlobal(SettingsModel $global): SettingsModel
    {
        $merged = clone $global;

        // Integer minimums: highest value wins
        if ($this->minLength !== null) {
            $merged->minLength = max($merged->minLength, $this->minLength);
        }
        if ($this->passwordHistoryCount !== null) {
            $merged->passwordHistoryCount = max($merged->passwordHistoryCount, $this->passwordHistoryCount);
        }
        if ($this->minimumCharacterTypes !== null) {
            $merged->minimumCharacterTypes = max($merged->minimumCharacterTypes, $this->minimumCharacterTypes);
        }

        // Integer maximums: lowest non-zero wins
        if ($this->maxLength !== null && $this->maxLength > 0) {
            if ($merged->maxLength === 0) {
                $merged->maxLength = $this->maxLength;
            } else {
                $merged->maxLength = min($merged->maxLength, $this->maxLength);
            }
        }

        // Boolean enablers: true wins
        if ($this->cases === true) {
            $merged->cases = true;
        }
        if ($this->numbers === true) {
            $merged->numbers = true;
        }
        if ($this->symbols === true) {
            $merged->symbols = true;
        }
        if ($this->pwned === true) {
            $merged->pwned = true;
        }
        if ($this->checkSequentialChars === true) {
            $merged->checkSequentialChars = true;
        }
        if ($this->checkRepeatedChars === true) {
            $merged->checkRepeatedChars = true;
        }
        if ($this->checkContextual === true) {
            $merged->checkContextual = true;
        }
        if ($this->checkCommonPasswords === true) {
            $merged->checkCommonPasswords = true;
        }

        // Complexity mode: 'individual' wins over 'minimum' (more prescriptive)
        if ($this->complexityMode !== null) {
            if ($this->complexityMode === 'individual' || $merged->complexityMode === 'individual') {
                $merged->complexityMode = 'individual';
            } else {
                $merged->complexityMode = $this->complexityMode;
            }
        }

        // Expiration: shortest period wins
        if ($this->expiryAmount !== null && $this->expiryPeriod !== null) {
            $groupDays = $this->_expiryToDays($this->expiryAmount, $this->expiryPeriod);
            $globalDays = $merged->expiryAmount !== null
                ? $this->_expiryToDays($merged->expiryAmount, $merged->expiryPeriod)
                : PHP_INT_MAX;

            if ($groupDays < $globalDays) {
                $merged->expiryAmount = $this->expiryAmount;
                $merged->expiryPeriod = $this->expiryPeriod;
            }
        }

        return $merged;
    }

    // Private Methods
    // =========================================================================

    /**
     * Converts an expiry amount and period to approximate days for comparison.
     *
     * @param int $amount
     * @param string $period
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _expiryToDays(int $amount, string $period): int
    {
        return match ($period) {
            'day' => $amount,
            'week' => $amount * 7,
            'month' => $amount * 30,
            'year' => $amount * 365,
            default => $amount,
        };
    }
}
