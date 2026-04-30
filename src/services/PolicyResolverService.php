<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\elements\User;
use craftpulse\passwordpolicy\models\GroupPolicyModel;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\base\Component;

/**
 * Class PolicyResolverService
 *
 * Resolves the effective password policy for a given user by merging
 * global settings with named per-group policies using "most restrictive wins" logic.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyResolverService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Resolves the effective password policy for a user.
     *
     * For Craft Solo or users with no groups, returns global settings.
     * For multi-group users, queries named policies from the database
     * and merges all applicable ones using "most restrictive wins" per setting type.
     *
     * @param User $user
     * @return SettingsModel
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resolveForUser(User $user): SettingsModel
    {
        $plugin = PasswordPolicy::$plugin;
        $settings = $plugin->getSettings();

        // If per-group policies are disabled or not Pro, return global
        if (!$plugin->getIsPro() || !$settings->enablePerGroupPolicies) {
            return $settings;
        }

        // Get user's groups
        $groups = $user->getGroups();

        if (empty($groups)) {
            return $settings;
        }

        // Query named policies for user's group IDs
        $groupIds = array_map(fn($g) => $g->id, $groups);
        $policies = $plugin->getPolicies()->getPoliciesForGroupIds($groupIds);

        if (empty($policies)) {
            return $settings;
        }

        $resolved = clone $settings;

        // Pre-pass: resolve booleans across all policies.
        // Any explicit true wins over any explicit false; absent means inherit.
        foreach (GroupPolicyModel::booleanOverrideFields() as $field) {
            $hasTrue = false;
            $hasFalse = false;
            foreach ($policies as $policy) {
                if ($policy->$field === true) {
                    $hasTrue = true;
                } elseif ($policy->$field === false) {
                    $hasFalse = true;
                }
            }
            if ($hasTrue) {
                $resolved->$field = true;
            } elseif ($hasFalse) {
                $resolved->$field = false;
            }
        }

        // Apply non-boolean merges sequentially (numerics, selects, expiry)
        foreach ($policies as $policy) {
            $resolved = $policy->mergeWithGlobal($resolved);
        }

        // Post-merge validation: maxLength must not be less than minLength.
        // When a policy bumps minLength above the configured maxLength, the
        // two bounds are incompatible. Drop the maxLength cap (set to 0 /
        // no limit) rather than forcing max = min — the minLength must be
        // honored for security, the maxLength cap is defensive only.
        if ($resolved->maxLength > 0 && $resolved->maxLength < $resolved->minLength) {
            Craft::warning(
                "Per-group policy merge produced invalid state: maxLength ({$resolved->maxLength}) < minLength ({$resolved->minLength}). Dropping maxLength cap (no upper limit).",
                'password-policy',
            );
            $resolved->maxLength = 0;
        }

        return $resolved;
    }
}
