<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\validators;

use Craft;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\validators\Validator;

/**
 * Class MinimumCharacterTypesValidator
 *
 * Validates that a password contains at least N of 4 character types:
 * uppercase, lowercase, digit, symbol. Active only when complexityMode
 * is 'minimum'. Mutually exclusive with individual cases/numbers/symbols toggles.
 *
 * Letter classes use Unicode property escapes (`\p{Ll}` / `\p{Lu}`) so
 * accented or non-Latin lowercase / uppercase letters count as letters,
 * not as symbols. The digit class is intentionally kept as `[0-9]` —
 * "digit" in password-policy context means an Arabic numeral that a user
 * typed off the number row, not every Unicode numeral (`²`, ⅓, ٤). The
 * symbol class is the residual: anything that isn't a Unicode letter
 * (`\p{L}`), a Unicode number (`\p{N}`), or a Unicode whitespace
 * separator (`\p{Z}`). Emoji, punctuation, and currency symbols all
 * count; whitespace doesn't.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class MinimumCharacterTypesValidator extends Validator
{
    // Public Properties
    // =========================================================================

    /**
     * Resolved per-user minimum-character-types requirement. Set by
     * `UserRules::defineRules()` / `ValidationController` from the user's
     * effective policy so a per-group override is enforced. Null falls back
     * to the global `SettingsModel` value (AJAX/preview without a target user).
     *
     * @var int|null
     */
    public ?int $minimumCharacterTypes = null;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateValue(#[\SensitiveParameter] $value): ?array
    {
        $required = $this->minimumCharacterTypes
            ?? PasswordPolicy::$plugin->getSettings()->minimumCharacterTypes;

        if ($required <= 0) {
            return null;
        }

        $count = 0;

        if (preg_match('/\p{Lu}/u', $value)) {
            $count++;
        }
        if (preg_match('/\p{Ll}/u', $value)) {
            $count++;
        }
        if (preg_match('/[0-9]/', $value)) {
            $count++;
        }
        if (preg_match('/[^\p{L}\p{N}\p{Z}]/u', $value)) {
            $count++;
        }

        if ($count < $required) {
            return [
                Craft::t(
                    'password-policy',
                    'Password must contain at least {count} of 4 character types (uppercase, lowercase, number, symbol).',
                    ['count' => $required],
                ),
                [],
            ];
        }

        return null;
    }
}
