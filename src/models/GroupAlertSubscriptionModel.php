<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use craft\base\Model;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\records\GroupAlertSubscriptionRecord;
use DateTime;

/**
 * Class GroupAlertSubscriptionModel
 *
 * Transport model for a row in `passwordpolicy_group_alert_subscriptions`.
 * Pairs with {@see GroupAlertSubscriptionRecord} — the read surfaces on
 * {@see \craftpulse\passwordpolicy\services\GroupAlertService} hydrate models
 * from records so callers (the CP editor, the dispatch path) never touch
 * ActiveRecord datetime-string quirks.
 *
 * Datetime columns come back from ActiveRecord as raw strings; `fromRecord()`
 * hydrates them via `DateTimeHelper::toDateTime()` per the project idiom
 * (direct assignment to `?DateTime` properties throws on a string).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupAlertSubscriptionModel extends Model
{
    // Static Methods
    // =========================================================================

    /**
     * Builds a model from a record, hydrating datetime strings into
     * `?DateTime` instances.
     *
     * @param GroupAlertSubscriptionRecord $record
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRecord(GroupAlertSubscriptionRecord $record): self
    {
        $model = new self();
        $model->id = (int)$record->id;
        $model->groupId = (int)$record->groupId;
        $model->eventType = (string)$record->eventType;
        $model->recipientEmail = (string)$record->recipientEmail;
        $model->enabled = (bool)$record->enabled;
        $model->dateCreated = DateTimeHelper::toDateTime($record->dateCreated) ?: null;
        $model->dateUpdated = DateTimeHelper::toDateTime($record->dateUpdated) ?: null;
        $model->uid = (string)$record->uid;

        return $model;
    }

    // Public Properties
    // =========================================================================

    /**
     * @var DateTime|null when the row was created.
     */
    public ?DateTime $dateCreated = null;

    /**
     * @var DateTime|null when the row was last updated.
     */
    public ?DateTime $dateUpdated = null;

    /**
     * @var bool whether the subscription is active. Disabled rows are kept
     *     for history but excluded from recipient resolution.
     */
    public bool $enabled = true;

    /**
     * @var string|null the alert event type this rule routes —
     *     `breach_detected` or `new_device`.
     */
    public ?string $eventType = null;

    /**
     * @var int|null the user group whose members trigger this routing rule.
     */
    public ?int $groupId = null;

    /**
     * @var int|null primary key.
     */
    public ?int $id = null;

    /**
     * @var string|null the security-contact email a copy of the alert is
     *     routed to.
     */
    public ?string $recipientEmail = null;

    /**
     * @var string|null UUID.
     */
    public ?string $uid = null;
}
