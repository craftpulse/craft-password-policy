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
use yii\validators\Validator;

/**
 * Class SequentialCharsValidator
 *
 * Detects 3+ ascending or descending sequential characters in passwords.
 * Catches letter sequences (abc, xyz), number sequences (123, 987), and
 * keyboard row sequences (qwerty, asdf).
 *
 * **Scope: ASCII only.** Both detection paths (the ASCII ord-diff scan and
 * the `KEYBOARD_SEQUENCES` substring check) operate on bytes / Latin
 * keyboard layouts. Non-ASCII alphabet walks (Greek `αβγ`, Cyrillic `абв`,
 * Hebrew `אבג`, etc.) are NOT flagged — by design, not by oversight. The
 * threat model is "user pattern-walks a Latin keyboard", which is locale-
 * agnostic: the keyboard layout is the same physical surface regardless of
 * the user's input language. Operators in non-Latin locales who want
 * non-ASCII sequence detection should request it as a separate feature; no
 * customer signal yet.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SequentialCharsValidator extends Validator
{
    // Const Properties
    // =========================================================================

    /**
     * Minimum length of sequential characters to flag.
     *
     * @var int
     */
    private const SEQUENCE_LENGTH = 3;

    /**
     * Keyboard row sequences to check against.
     *
     * @var string[]
     */
    private const KEYBOARD_SEQUENCES = [
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm',
        '1234567890',
    ];

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
        $lower = strtolower($value);

        if ($this->_hasAsciiSequence($lower) || $this->_hasKeyboardSequence($lower)) {
            return [
                Craft::t(
                    'password-policy',
                    'Password must not contain sequential characters (e.g., abc, 123, qwerty).',
                ),
                [],
            ];
        }

        return null;
    }

    // Private Methods
    // =========================================================================

    /**
     * Checks for ascending or descending ASCII character sequences.
     *
     * @param string $value
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hasAsciiSequence(string $value): bool
    {
        $length = strlen($value);

        if ($length < self::SEQUENCE_LENGTH) {
            return false;
        }

        $ascending = 1;
        $descending = 1;

        for ($i = 1; $i < $length; $i++) {
            $diff = ord($value[$i]) - ord($value[$i - 1]);

            if ($diff === 1) {
                $ascending++;
                $descending = 1;
            } elseif ($diff === -1) {
                $descending++;
                $ascending = 1;
            } else {
                $ascending = 1;
                $descending = 1;
            }

            if ($ascending >= self::SEQUENCE_LENGTH || $descending >= self::SEQUENCE_LENGTH) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks for keyboard row sequences.
     *
     * @param string $value
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hasKeyboardSequence(string $value): bool
    {
        foreach (self::KEYBOARD_SEQUENCES as $sequence) {
            $reversed = strrev($sequence);

            for ($i = 0; $i <= strlen($sequence) - self::SEQUENCE_LENGTH; $i++) {
                $chunk = substr($sequence, $i, self::SEQUENCE_LENGTH);
                $reversedChunk = substr($reversed, $i, self::SEQUENCE_LENGTH);

                if (str_contains($value, $chunk) || str_contains($value, $reversedChunk)) {
                    return true;
                }
            }
        }

        return false;
    }
}
