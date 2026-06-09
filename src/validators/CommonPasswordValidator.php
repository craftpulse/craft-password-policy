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
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\validators\Validator;

/**
 * Class CommonPasswordValidator
 *
 * Validates passwords against the blocklist table (common + custom entries).
 *
 * Reads the cached full-table projection from `BlocklistService` once per
 * request, then filters the result against `$policyIds` so each call only
 * sees the rows in scope for the user being validated:
 *
 *  - `policyIds = null` (default): global rows only (`policyId IS NULL`).
 *    Used for Pro/Lite installs and for any caller that doesn't resolve
 *    a target user (e.g. the front-end registration form).
 *  - `policyIds = [int, ...]`: global rows + the per-policy rows tagged
 *    with any of those IDs. Used by Enterprise installs, populated by
 *    `UserRules::defineRules()` and `ValidationController::actionValidate()`
 *    via `PolicyResolverService`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class CommonPasswordValidator extends Validator
{
    // Public Properties
    // =========================================================================

    /**
     * Policy IDs the validator should consider per-policy blocklist rows for.
     *
     * `null` is the legacy / Pro / Lite default — only global rows
     * (`policyId IS NULL`) match. An array (potentially empty) opts into
     * per-policy filtering: an empty array still matches global rows but
     * never any per-policy rows. Populated by `UserRules` and the AJAX
     * validation endpoint after resolving the target user via
     * `PolicyResolverService`. Yii populates the property from validator
     * config (`['policyIds' => $ids]`) before `init()`.
     *
     * @var int[]|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public ?array $policyIds = null;

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
        $word = strtolower(trim($value));
        $blocklist = $this->_getScopedBlocklist();

        if (!isset($blocklist[$word])) {
            return null;
        }

        // The custom blocklist editor is a Pro feature. Common-password
        // enforcement stays universal across editions, but a `custom`
        // match must not fire on a sub-Pro install — a Lite install that
        // still holds custom rows (e.g. seeded under Pro, then downgraded)
        // would otherwise enforce a Pro-only blocklist it can no longer
        // edit. Common matches always enforce regardless of edition.
        if ($blocklist[$word] === 'custom' && !PasswordPolicy::$plugin->getIsPro()) {
            return null;
        }

        $message = $blocklist[$word] === 'custom'
            ? Craft::t(
                'password-policy',
                'This password is blocked. Please choose a different one.',
            )
            : Craft::t(
                'password-policy',
                'This password is too common. Please choose a more unique password.',
            );

        return [$message, []];
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the blocklist projection scoped to `$this->policyIds`.
     *
     * Delegates to `BlocklistService::getWordsForPolicies()` (single
     * cached read of the full table, in-memory filter on policyId)
     * instead of holding its own cache key — the per-validator
     * filter shape would fragment cache space across N-policy
     * combinations.
     *
     * @return array<string, string> word → source ('common' | 'custom')
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getScopedBlocklist(): array
    {
        return PasswordPolicy::$plugin->getBlocklist()->getWordsForPolicies(
            $this->policyIds ?? [],
        );
    }
}
