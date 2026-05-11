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
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use DateTime;

/**
 * Class NotificationLogQuery
 *
 * Element-query for {@see NotificationLogElement}. Pairs the standard
 * Craft element-index plumbing (status, search, sort, paginate, source
 * filtering) with the custom params the activity surface depends on —
 * `userId`, `notificationType`, `recipientEmail`, `sentBefore` /
 * `sentAfter`, `resentFromId`.
 *
 * Default ordering is `sentAt DESC` so the activity index lands on the
 * newest sends without an explicit `orderBy()` call.
 *
 * @method NotificationLogElement[]|array all($db = null)
 * @method NotificationLogElement|array|null one($db = null)
 * @method NotificationLogElement|array|null nth(int $n, $db = null)
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationLogQuery extends ElementQuery
{
    // Public Properties
    // =========================================================================

    /**
     * @var mixed filter by notification type machine-key (`expiry_reminder`,
     *     `breach_detected`, `new_device`, `admin_alert_*`)
     */
    public mixed $notificationType = null;

    /**
     * @var mixed filter by raw recipient email address
     */
    public mixed $recipientEmail = null;

    /**
     * @var mixed filter by the self-FK pointer (resend chain)
     */
    public mixed $resentFromId = null;

    /**
     * @var DateTime|null only return rows sent strictly after this datetime
     */
    public ?DateTime $sentAfter = null;

    /**
     * @var DateTime|null only return rows sent strictly before this datetime
     */
    public ?DateTime $sentBefore = null;

    /**
     * @var mixed filter by the site this notification rendered under
     */
    public mixed $siteIdParam = null;

    /**
     * @var mixed filter by the user the notification was sent to. Distinct
     *     from the element's own `userId` because the user column on the
     *     notification log is nullable since 5.2.0 (`SET NULL` on user
     *     hard-delete to outlive the entity).
     */
    public mixed $userId = null;

    /**
     * @var array<string, int> default ordering — newest first.
     */
    protected array $defaultOrderBy = ['passwordpolicy_notification_log.sentAt' => SORT_DESC];

    // Public Methods
    // =========================================================================

    /**
     * Filters by notification type machine-key.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function notificationType(mixed $value): static
    {
        $this->notificationType = $value;

        return $this;
    }

    /**
     * Filters by raw recipient email address.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recipientEmail(mixed $value): static
    {
        $this->recipientEmail = $value;

        return $this;
    }

    /**
     * Filters by the self-FK pointer (resend chain).
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resentFromId(mixed $value): static
    {
        $this->resentFromId = $value;

        return $this;
    }

    /**
     * Filters to rows sent strictly after `$value`.
     *
     * @param DateTime $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sentAfter(DateTime $value): static
    {
        $this->sentAfter = $value;

        return $this;
    }

    /**
     * Filters to rows sent strictly before `$value`.
     *
     * @param DateTime $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sentBefore(DateTime $value): static
    {
        $this->sentBefore = $value;

        return $this;
    }

    /**
     * Filters by the site this notification rendered under. The
     * parameter is named `siteIdParam` on the query rather than
     * `siteId` to avoid colliding with the inherited `siteId` setter
     * that scopes the element index to a Craft site.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function siteIdParam(mixed $value): static
    {
        $this->siteIdParam = $value;

        return $this;
    }

    /**
     * Filters by the user the notification was sent to.
     *
     * @param mixed $value
     * @return static
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function userId(mixed $value): static
    {
        $this->userId = $value;

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
        $this->joinElementTable('passwordpolicy_notification_log');

        $this->query->addSelect([
            'passwordpolicy_notification_log.userId',
            'passwordpolicy_notification_log.notificationType',
            'passwordpolicy_notification_log.status',
            'passwordpolicy_notification_log.recipientEmail',
            'passwordpolicy_notification_log.siteId',
            'passwordpolicy_notification_log.subject',
            'passwordpolicy_notification_log.body',
            'passwordpolicy_notification_log.errorMessage',
            'passwordpolicy_notification_log.resentFromId',
            'passwordpolicy_notification_log.sentAt',
        ]);

        if ($this->notificationType !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_notification_log.notificationType',
                $this->notificationType,
            ));
        }

        if ($this->recipientEmail !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_notification_log.recipientEmail',
                $this->recipientEmail,
            ));
        }

        if ($this->resentFromId !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_notification_log.resentFromId',
                $this->resentFromId,
            ));
        }

        if ($this->sentAfter !== null) {
            $this->subQuery->andWhere(['>=', 'passwordpolicy_notification_log.sentAt', Db::prepareDateForDb($this->sentAfter)]);
        }

        if ($this->sentBefore !== null) {
            $this->subQuery->andWhere(['<=', 'passwordpolicy_notification_log.sentAt', Db::prepareDateForDb($this->sentBefore)]);
        }

        if ($this->siteIdParam !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_notification_log.siteId',
                $this->siteIdParam,
            ));
        }

        if ($this->userId !== null) {
            $this->subQuery->andWhere(Db::parseParam(
                'passwordpolicy_notification_log.userId',
                $this->userId,
            ));
        }

        return parent::beforePrepare();
    }

    /**
     * @inheritdoc
     *
     * Maps element-index status keys to SQL conditions on
     * `notification_log.status`. `NotificationStatus::values()` is the
     * single source of truth for the valid keys; the element's
     * `statuses()` method draws from the same enum.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function statusCondition(string $status): mixed
    {
        if (in_array($status, NotificationStatus::values(), true)) {
            return ['passwordpolicy_notification_log.status' => $status];
        }

        return parent::statusCondition($status);
    }
}
