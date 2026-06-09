<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\rules;

use Craft;
use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\validators\CommonPasswordValidator;
use craftpulse\passwordpolicy\validators\ContextualValidator;
use craftpulse\passwordpolicy\validators\HibpValidator;
use craftpulse\passwordpolicy\validators\MinimumCharacterTypesValidator;
use craftpulse\passwordpolicy\validators\PasswordHistoryValidator;
use craftpulse\passwordpolicy\validators\RepeatedCharsValidator;
use craftpulse\passwordpolicy\validators\SequentialCharsValidator;

/**
 * Class UserRules
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class UserRules
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the validation rules for user password fields.
     *
     * When a User instance is provided, the rules use that user's effective
     * policy (global merged with any per-group overrides via the resolver).
     * When null, falls back to global settings — used for AJAX validation
     * and other contexts without a target user.
     *
     * @param User|null $user the user whose password is being validated
     * @return array
     *
     * @author CraftPulse
     * @since 5.0.0
     */
    public static function defineRules(?User $user = null): array
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $user !== null
            ? $plugin->getPolicyResolver()->resolveForUser($user)
            : $plugin->getSettings();
        $isPro = $plugin->getIsPro();

        // Min length (always)
        $rules[] = [
            ['password', 'newPassword'],
            'string',
            'min' => $settings->minLength,
            'tooShort' => Craft::t(
                'password-policy',
                'Password must contain at least {min} characters.',
                ['min' => $settings->minLength],
            ),
            'skipOnError' => false,
        ];

        // Complexity: individual toggles or minimum character types
        if ($isPro && $settings->complexityMode === 'minimum' && $settings->minimumCharacterTypes > 0) {
            // "X of 4 character types" mode — mutually exclusive with individual
            // toggles. Thread the resolved per-user count into the validator so a
            // per-group override is enforced rather than the global setting.
            $rules[] = [
                ['password', 'newPassword'],
                MinimumCharacterTypesValidator::class,
                'minimumCharacterTypes' => $settings->minimumCharacterTypes,
                'skipOnError' => false,
            ];
        } else {
            // Individual toggle mode (default). Pass the resolved settings into
            // the pattern/message builders so per-group complexity toggles win.
            $rules[] = [
                ['password', 'newPassword'],
                'match',
                'pattern' => PasswordPolicy::$plugin->getPasswords()->generatePattern($settings),
                'message' => Craft::t(
                        'password-policy',
                        'Your password must contain at least one of each of the following: ',
                    ) . PasswordPolicy::$plugin->getPasswords()->generateMessage($settings),
                'skipOnError' => false,
            ];
        }

        // Max length — enforce whenever a non-zero cap is set. The resolver
        // guarantees max >= min after any cross-policy auto-correction, so
        // we don't need a separate `> minLength` guard here (which would
        // skip the valid `max == min` case).
        if ($settings->maxLength > 0) {
            $rules[] = [
                ['password', 'newPassword'],
                'string',
                'max' => $settings->maxLength,
                'tooLong' => Craft::t(
                    'password-policy',
                    'Password can maximum contain {max} characters.',
                    ['max' => $settings->maxLength],
                ),
                'skipOnError' => false,
            ];
        }

        // Sequential characters (Pro+)
        if ($isPro && $settings->checkSequentialChars) {
            $rules[] = [
                ['password', 'newPassword'],
                SequentialCharsValidator::class,
                'skipOnError' => false,
            ];
        }

        // Repeated characters (Pro+)
        if ($isPro && $settings->checkRepeatedChars) {
            $rules[] = [
                ['password', 'newPassword'],
                RepeatedCharsValidator::class,
                'skipOnError' => false,
            ];
        }

        // Contextual check (Pro+)
        if ($isPro && $settings->checkContextual) {
            $rules[] = [
                ['password', 'newPassword'],
                ContextualValidator::class,
                'skipOnError' => false,
            ];
        }

        // Common password blocklist (all editions since 5.2.0).
        //
        // Enterprise resolves the user's applicable policy IDs and passes
        // them to the validator so per-policy custom blocklist entries
        // (G6) can filter into the merged set. Pro/Lite leave `policyIds`
        // null — the validator falls back to global-only matching against
        // the bundled list, which is the pre-G6 behavior.
        if ($settings->checkCommonPasswords) {
            $config = [
                ['password', 'newPassword'],
                CommonPasswordValidator::class,
                'skipOnError' => false,
            ];

            if ($plugin->getIsEnterprise() && $user !== null) {
                $config['policyIds'] = self::_resolveUserPolicyIds($user);
            }

            $rules[] = $config;
        }

        // HIBP check (after content rules — external API call, slower)
        if ($settings->hibp) {
            $rules[] = [
                ['password', 'newPassword'],
                HibpValidator::class,
                'skipOnError' => false,
            ];
        }

        // Password history check last (gating handled inside validator). Thread
        // the resolved per-user count through so a per-group history-depth
        // override is enforced — the validator falls back to the global count
        // only when null (AJAX/preview contexts without a target user).
        if ($settings->passwordHistoryCount > 0) {
            $rules[] = [
                ['password', 'newPassword'],
                PasswordHistoryValidator::class,
                'passwordHistoryCount' => $settings->passwordHistoryCount,
                'skipOnError' => false,
            ];
        }

        return $rules;
    }

    // Private Methods
    // =========================================================================

    /**
     * Resolves the policy IDs that apply to the given user, ordered by
     * `sortOrder ASC`. Empty when per-group policies are disabled or the
     * user has no group-policy match — the validator then sees only
     * global blocklist rows (`policyId IS NULL`), preserving the pre-G6
     * behavior on Enterprise installs that haven't authored any per-
     * policy custom entries yet.
     *
     * @param User $user the user being validated
     * @return int[] the policy IDs the validator should scope to
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _resolveUserPolicyIds(User $user): array
    {
        $plugin = PasswordPolicy::$plugin;

        if (!$plugin->getSettings()->enablePerGroupPolicies) {
            return [];
        }

        $groups = $user->getGroups();

        if (empty($groups)) {
            return [];
        }

        $groupIds = array_map(fn($g) => (int)$g->id, $groups);
        $policies = $plugin->getPolicies()->getPoliciesForGroupIds($groupIds);

        return array_values(array_filter(array_map(
            fn($policy) => $policy->id !== null ? (int)$policy->id : null,
            $policies,
        )));
    }
}
