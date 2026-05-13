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
use craftpulse\passwordpolicy\elements\AuditLogElement;
use DateTime;

/**
 * Class AuditLogQuery
 *
 * Element-query for {@see AuditLogElement}. Pairs the standard Craft
 * element-index plumbing (status, search, sort, paginate, source
 * filtering) with the custom params the compliance dashboard + future
 * G3 surface depends on — `event`, `auditUserId` (avoiding any
 * potential collision with future element-query `userId` semantics),
 * `changedByUserId`, `outcome`, `source`, `dateCreatedBefore` /
 * `dateCreatedAfter`, `forwardedAt` (null-or-not for forwarder-backlog
 * queries).
 *
 * Default ordering is `passwordpolicy_audit_log.dateCreated DESC` so
 * the audit index lands on the newest events without an explicit
 * `orderBy()` call.
 *
 * **Verifier + forwarders + export stay on raw queries.** Per Step 5
 * invariant L4, `password-policy/audit/verify`, `SiemForwardJob`,
 * `WebhookForwardJob`, `AuditExportJob`, and the G1 recompute
 * migration read raw audit rows via `(new Query())->from('audit_log')`
 * — the element layer is additive (CP index + condition rules + G3
 * dashboard), not a substitute for the raw chain walk.
 *
 * @method AuditLogElement[]|array all($db = null)
 * @method AuditLogElement|array|null one($db = null)
 * @method AuditLogElement|array|null nth(int $n, $db = null)
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditLogQuery extends ElementQuery
{
    // Public Properties
    // =========================================================================

    /**
     * @var mixed filter by the audit row's `userId` column. Named
     *     `auditUserId` on the query rather than `userId` to keep room
     *     for the inherited element-query `userId` semantics (Craft has
     *     no `userId` setter today, but element-query subclasses can
     *     shadow base properties — being explicit avoids that surprise
     *     for a downstream G3 author).
     */
    public mixed $auditUserId = null;

    /**
     * @var mixed filter by the actor (admin) user-id who triggered the
     *     event. Pair with `auditUserId` to find rows where admin A
     *     acted on user B.
     */
    public mixed $changedByUserId = null;

    /**
     * @var DateTime|null only return rows whose `dateCreated` is
     *     greater than or equal to this datetime. Inclusive bound.
     */
    public ?DateTime $dateCreatedAfter = null;

    /**
     * @var DateTime|null only return rows whose `dateCreated` is less
     *     than or equal to this datetime. Inclusive bound.
     */
    public ?DateTime $dateCreatedBefore = null;

    /**
     * @var mixed filter by event machine-key. Values MUST match an
     *     allowlist key in `AuditLogService::ALLOWED_DETAILS_BY_EVENT`
     *     to return rows (events fired without a registry entry never
     *     get persisted).
     */
    public mixed $event = null;

    /**
     * @var mixed filter by `forwardedAt`. `false` returns rows where
     *     `forwardedAt IS NULL` (forwarder backlog); `true` returns
     *     rows where `forwardedAt IS NOT NULL`; a datetime narrows to
     *     a specific timestamp. Anything else delegates to
     *     `Db::parseParam()`.
     */
    public mixed $forwardedAt = null;

    /**
     * @var mixed filter by `outcome` column — `success` or `failure`.
     */
    public mixed $outcome = null;

    /**
     * @var mixed filter by `source` context — `admin`, `self-service`,
     *     `cli`, etc.
     */
    public mixed $source = null;

    /**
     * @var array<string, int> default ordering — newest first.
     */
    protected array $defaultOrderBy = ['passwordpolicy_audit_log.dateCreated' => SORT_DESC];

    // Public Methods
    // =========================================================================

    /**
     * Filters by the audit row's `userId` column.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function auditUserId(mixed $value): static
    {
        $this->auditUserId = $value;

        return $this;
    }

    /**
     * Filters by the actor (admin) user-id.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function changedByUserId(mixed $value): static
    {
        $this->changedByUserId = $value;

        return $this;
    }

    /**
     * Filters to rows with `dateCreated >= $value`.
     *
     * @param DateTime $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function dateCreatedAfter(DateTime $value): static
    {
        $this->dateCreatedAfter = $value;

        return $this;
    }

    /**
     * Filters to rows with `dateCreated <= $value`.
     *
     * @param DateTime $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function dateCreatedBefore(DateTime $value): static
    {
        $this->dateCreatedBefore = $value;

        return $this;
    }

    /**
     * Filters by event machine-key.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function event(mixed $value): static
    {
        $this->event = $value;

        return $this;
    }

    /**
     * Filters by `forwardedAt`. Pass `false` for "unforwarded" (NULL),
     * `true` for "forwarded" (NOT NULL), a `DateTime` for a literal
     * match, or any value that `Db::parseParam()` accepts.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function forwardedAt(mixed $value): static
    {
        $this->forwardedAt = $value;

        return $this;
    }

    /**
     * Filters by `outcome` — `success` / `failure`.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function outcome(mixed $value): static
    {
        $this->outcome = $value;

        return $this;
    }

    /**
     * Filters by `source` context.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function source(mixed $value): static
    {
        $this->source = $value;

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
        $this->joinElementTable('passwordpolicy_audit_log');

        $this->query->addSelect([
            'passwordpolicy_audit_log.userId',
            'passwordpolicy_audit_log.changedByUserId',
            'passwordpolicy_audit_log.event',
            'passwordpolicy_audit_log.outcome',
            'passwordpolicy_audit_log.source',
            'passwordpolicy_audit_log.details',
            'passwordpolicy_audit_log.ipHash',
            'passwordpolicy_audit_log.userIdentifier',
            'passwordpolicy_audit_log.rowHash',
            'passwordpolicy_audit_log.previousHash',
            'passwordpolicy_audit_log.forwardedAt',
            'passwordpolicy_audit_log.forwardAttempts',
        ]);

        if ($this->auditUserId !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_audit_log.userId',
                $this->auditUserId,
            ));
        }

        if ($this->changedByUserId !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_audit_log.changedByUserId',
                $this->changedByUserId,
            ));
        }

        if ($this->dateCreatedAfter !== null) {
            $this->subQuery->andWhere([
                '>=',
                'passwordpolicy_audit_log.dateCreated',
                Db::prepareDateForDb($this->dateCreatedAfter),
            ]);
        }

        if ($this->dateCreatedBefore !== null) {
            $this->subQuery->andWhere([
                '<=',
                'passwordpolicy_audit_log.dateCreated',
                Db::prepareDateForDb($this->dateCreatedBefore),
            ]);
        }

        if ($this->event !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_audit_log.event',
                $this->event,
            ));
        }

        if ($this->forwardedAt !== null) {
            if ($this->forwardedAt === false) {
                $this->subQuery->andWhere(['passwordpolicy_audit_log.forwardedAt' => null]);
            } elseif ($this->forwardedAt === true) {
                $this->subQuery->andWhere(['not', ['passwordpolicy_audit_log.forwardedAt' => null]]);
            } else {
                $this->subQuery->andWhere(Db::parseParam(
                    'passwordpolicy_audit_log.forwardedAt',
                    $this->forwardedAt,
                ));
            }
        }

        if ($this->outcome !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_audit_log.outcome',
                $this->outcome,
            ));
        }

        if ($this->source !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_audit_log.source',
                $this->source,
            ));
        }

        return parent::beforePrepare();
    }

    /**
     * @inheritdoc
     *
     * Maps element-index status keys (`success` / `failure`) to SQL
     * conditions on `passwordpolicy_audit_log.outcome`. The element's
     * {@see AuditLogElement::statuses()} method is the single source
     * of truth for the valid keys.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function statusCondition(string $status): mixed
    {
        if (in_array($status, ['success', 'failure'], true)) {
            return ['passwordpolicy_audit_log.outcome' => $status];
        }

        return parent::statusCondition($status);
    }
}
