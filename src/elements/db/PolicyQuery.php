<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\db;

use craft\elements\db\ElementQuery;
use craft\helpers\Db;
use craftpulse\passwordpolicy\elements\PolicyElement;

/**
 * Class PolicyQuery
 *
 * Element-query for {@see PolicyElement}. Pairs the standard Craft
 * element-index plumbing (status, search, sort, paginate, source
 * filtering) with the custom params the policy index + future
 * downstream consumers depend on — `handle`, `preset`, `groupId`.
 *
 * The `groupId` setter joins the `passwordpolicy_policy_groups`
 * junction so callers can "find policies assigned to a given user
 * group" without a separate service round-trip — mirrors
 * `PolicyService::getPoliciesForGroupIds()` via the element-query
 * surface.
 *
 * Default ordering is `passwordpolicy_policies.sortOrder ASC` so the
 * policy index lands on the canonical precedence without an explicit
 * `orderBy()` call.
 *
 * @method PolicyElement[]|array all($db = null)
 * @method PolicyElement|array|null one($db = null)
 * @method PolicyElement|array|null nth(int $n, $db = null)
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyQuery extends ElementQuery
{
    // Public Properties
    // =========================================================================

    /**
     * @var mixed filter by `passwordpolicy_policy_groups.groupId` —
     *     joins the junction so the query returns policies assigned to
     *     the matching user group(s)
     */
    public mixed $groupId = null;

    /**
     * @var mixed filter by `handle` column
     */
    public mixed $handle = null;

    /**
     * @var mixed filter by `preset` column (e.g. `nist-800-63b`,
     *     `owasp-asvs`, `pci-dss-v4`, `strict-enterprise`, or null for
     *     custom policies)
     */
    public mixed $preset = null;

    /**
     * @var array<string, int> default ordering — canonical precedence
     */
    protected array $defaultOrderBy = ['passwordpolicy_policies.sortOrder' => SORT_ASC];

    // Public Methods
    // =========================================================================

    /**
     * Filters to policies assigned to the given user group(s). Joins
     * `passwordpolicy_policy_groups` and filters on `groupId`.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function groupId(mixed $value): static
    {
        $this->groupId = $value;

        return $this;
    }

    /**
     * Filters by `handle` column.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function handle(mixed $value): static
    {
        $this->handle = $value;

        return $this;
    }

    /**
     * Filters by `preset` column.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function preset(mixed $value): static
    {
        $this->preset = $value;

        return $this;
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function beforePrepare(): bool
    {
        $this->joinElementTable('passwordpolicy_policies');

        $this->query->addSelect([
            'passwordpolicy_policies.name',
            'passwordpolicy_policies.handle',
            'passwordpolicy_policies.preset',
            'passwordpolicy_policies.settings',
            'passwordpolicy_policies.sortOrder',
        ]);

        if ($this->handle !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_policies.handle',
                $this->handle,
            ));
        }

        if ($this->preset !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_policies.preset',
                $this->preset,
            ));
        }

        if ($this->groupId !== null) {
            $this->subQuery->innerJoin(
                ['passwordpolicy_policy_groups' => '{{%passwordpolicy_policy_groups}}'],
                '[[passwordpolicy_policy_groups.policyId]] = [[passwordpolicy_policies.id]]',
            );
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_policy_groups.groupId',
                $this->groupId,
            ));
            // De-duplicate when a policy is assigned to multiple groups
            // matching the filter — single policy, single row.
            $this->subQuery->groupBy('passwordpolicy_policies.id');
        }

        return parent::beforePrepare();
    }

    /**
     * @inheritdoc
     *
     * Maps element-index status keys to no-op conditions. Every saved
     * policy is `enabled` in 5.2.0; the `disabled` slot reserved on
     * {@see PolicyElement::statuses()} doesn't bind to a column today
     * — selecting the `disabled` source returns no rows (empty
     * `0 = 1` condition).
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function statusCondition(string $status): mixed
    {
        if ($status === 'enabled') {
            return [];
        }

        if ($status === 'disabled') {
            return ['0' => '1'];
        }

        return parent::statusCondition($status);
    }
}
