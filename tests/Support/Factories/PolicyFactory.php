<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support\Factories;

use craft\models\UserGroup;
use craftpulse\passwordpolicy\enums\PolicyPreset;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\Exception;

/**
 * Test factory for `PolicyModel` instances persisted via `PolicyService`.
 *
 * Resolver tests need real DB-backed policies because the resolver queries
 * `PolicyService::getPoliciesForGroupIds()` — purely in-memory models won't
 * exercise the JSON encode/decode roundtrip or the junction-table merge.
 * The factory wraps `PolicyService::savePolicy()` so each persisted policy
 * runs through the same path as production code.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Persists a NIST 800-63B preset policy and assigns it to the given
     * groups (if any). Returns the saved model with `id` populated.
     *
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function nist(array $groups = []): PolicyModel
    {
        return self::fromPreset(PolicyPreset::NIST_800_63B, $groups);
    }

    /**
     * Persists an OWASP ASVS preset policy and assigns it to the given
     * groups (if any). Returns the saved model with `id` populated.
     *
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function owasp(array $groups = []): PolicyModel
    {
        return self::fromPreset(PolicyPreset::OWASP_ASVS, $groups);
    }

    /**
     * Persists a Strict Enterprise preset policy and assigns it to the
     * given groups (if any). Returns the saved model with `id` populated.
     *
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function strict(array $groups = []): PolicyModel
    {
        return self::fromPreset(PolicyPreset::STRICT_ENTERPRISE, $groups);
    }

    /**
     * Persists a PCI-DSS v4.0 preset policy and assigns it to the given
     * groups (if any). Returns the saved model with `id` populated.
     *
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pciDss(array $groups = []): PolicyModel
    {
        return self::fromPreset(PolicyPreset::PCI_DSS_V4, $groups);
    }

    /**
     * Persists a custom policy with arbitrary overrides and assigns it
     * to the given groups (if any). Pass `name` and `handle` to override
     * the auto-generated test defaults; any other key in `$overrides`
     * lands on the matching settings field.
     *
     * @param array<string, mixed> $overrides
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function custom(array $overrides = [], array $groups = []): PolicyModel
    {
        $unique = bin2hex(random_bytes(4));
        $name = $overrides['name'] ?? "Test Policy {$unique}";
        $handle = $overrides['handle'] ?? "testPolicy{$unique}";

        unset($overrides['name'], $overrides['handle']);

        $policy = new PolicyModel();
        $policy->name = (string)$name;
        $policy->handle = (string)$handle;

        foreach ($overrides as $field => $value) {
            $policy->{$field} = $value;
        }

        return self::save($policy, $groups);
    }

    /**
     * Saves the given (in-memory) policy and assigns it to the given groups.
     * Lower-level entry point — most tests want `nist()` / `owasp()` /
     * `custom()`.
     *
     * @param PolicyModel $policy
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function save(PolicyModel $policy, array $groups = []): PolicyModel
    {
        $groupIds = array_map(fn(UserGroup $group) => (int)$group->id, $groups);

        $service = PasswordPolicy::$plugin->getPolicies();

        if (!$service->savePolicy($policy, $groupIds)) {
            throw new Exception(sprintf(
                'PolicyFactory::save failed to save policy: %s',
                implode('; ', $policy->getFirstErrors()),
            ));
        }

        return $policy;
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds a `PolicyModel` from a `PolicyPreset`, names + handles it
     * uniquely, and persists it. Shared backbone for `nist()` / `owasp()` /
     * `strict()` / `pciDss()`.
     *
     * @param PolicyPreset $preset
     * @param UserGroup[] $groups
     * @return PolicyModel
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function fromPreset(PolicyPreset $preset, array $groups): PolicyModel
    {
        $unique = bin2hex(random_bytes(4));
        $groupPolicy = $preset->toGroupPolicy();

        $policy = new PolicyModel();
        $policy->name = "{$preset->label()} {$unique}";
        $policy->handle = "preset{$preset->name}{$unique}";
        $policy->preset = $preset->value;

        foreach (PolicyModel::settingsFields() as $field) {
            if (property_exists($groupPolicy, $field) && $groupPolicy->{$field} !== null) {
                $policy->{$field} = $groupPolicy->{$field};
            }
        }

        return self::save($policy, $groups);
    }
}
