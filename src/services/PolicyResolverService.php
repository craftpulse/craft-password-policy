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
 * global settings with per-group overrides using "most restrictive wins" logic.
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
     * For multi-group users, merges all applicable group policies using
     * "most restrictive wins" per setting type.
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

        $groupPolicies = $settings->groupPolicies;

        if (empty($groupPolicies)) {
            return $settings;
        }

        // Get user's groups
        $groups = $user->getGroups();

        if (empty($groups)) {
            return $settings;
        }

        // Collect applicable group policies
        $applicablePolicies = [];
        foreach ($groups as $group) {
            if (isset($groupPolicies[$group->uid])) {
                $policyData = $groupPolicies[$group->uid];
                $groupPolicy = new GroupPolicyModel();

                if (is_array($policyData)) {
                    $groupPolicy->setAttributes($policyData, false);
                }

                $applicablePolicies[] = $groupPolicy;
            }
        }

        if (empty($applicablePolicies)) {
            return $settings;
        }

        // Merge all group policies with global: "most restrictive wins"
        $resolved = clone $settings;

        foreach ($applicablePolicies as $groupPolicy) {
            $resolved = $groupPolicy->mergeWithGlobal($resolved);
        }

        // Post-merge validation: maxLength must not be less than minLength
        if ($resolved->maxLength > 0 && $resolved->maxLength < $resolved->minLength) {
            Craft::warning(
                "Per-group policy merge produced invalid state: maxLength ({$resolved->maxLength}) < minLength ({$resolved->minLength}). Using minLength as effective maxLength.",
                'password-policy',
            );
            $resolved->maxLength = $resolved->minLength;
        }

        return $resolved;
    }
}
