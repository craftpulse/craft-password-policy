<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements;

use Craft;
use craft\base\Element;
use craft\elements\actions\Delete;
use craft\elements\actions\Restore;
use craft\elements\User;
use craft\helpers\Cp;
use craft\helpers\DateTimeHelper;
use craft\helpers\Db;
use craft\helpers\Html;
use craft\helpers\UrlHelper;
use craftpulse\passwordpolicy\elements\actions\ResendNotification;
use craftpulse\passwordpolicy\elements\db\NotificationLogQuery;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use DateTime;
use Exception;

/**
 * Class NotificationLogElement
 *
 * Craft element wrapper around `passwordpolicy_notification_log`. Pairs
 * with {@see NotificationLogRecord}: the element provides the queryable
 * + index surface, the record stays the storage layer. Element id IS
 * record id IS `craft_elements.id`.
 *
 * **Capture invariant:** the plugin's `NotificationService` saves an
 * element row for every send attempt — both successes and failures.
 * That invariant lives in the service; this element wraps the row for
 * the index / detail / resend / delete surfaces and contributes no
 * write paths of its own.
 *
 * **Edition gating:** capture is universal, exposure is gated. The
 * Pro-only `Notifications → Activity` subnav renders the native
 * element index against this class; Lite installs still write the
 * rows but can't navigate to them via the CP. See
 * `project_audit_capture_principle.md`.
 *
 * **Soft-delete + restore.** Element soft-delete (via `dateDeleted` on
 * `craft_elements`) leaves the audit row visible (filterable via the
 * "trashed" element-index source). Element hard-delete cascades a row
 * drop via the FK on `notification_log.id`. `userId` is nullable +
 * `SET NULL` so notification history outlives the user.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationLogElement extends Element
{
    // Public Properties
    // =========================================================================

    /**
     * @var ?string body of the rendered notification — Twig output, plain text
     */
    public ?string $body = null;

    /**
     * @var ?string `Throwable::getMessage()` captured on the failure path
     */
    public ?string $errorMessage = null;

    /**
     * @var ?string machine-key for the kind of notification — `expiry_reminder`,
     *     `breach_detected`, `new_device`, `admin_alert_*`
     */
    public ?string $notificationType = null;

    /**
     * @var ?string raw recipient address the mail went to
     */
    public ?string $recipientEmail = null;

    /**
     * @var ?int self-FK pointer — when set, this row is the result of a
     *     resend of the row with this id
     */
    public ?int $resentFromId = null;

    /**
     * @var ?DateTime when the dispatch attempt completed (success or failure)
     */
    public ?DateTime $sentAt = null;

    /**
     * @var ?int site the template rendered under
     */
    public ?int $siteIdValue = null;

    /**
     * @var ?string `sent` / `failed` — backed by {@see NotificationStatus}
     */
    public ?string $status = null;

    /**
     * @var ?string rendered Twig output of the template's subject line
     */
    public ?string $subject = null;

    /**
     * @var ?int the user the notification was sent to. Nullable since 5.2.0
     *     — `SET NULL` on user hard-delete so the audit row outlives the
     *     entity.
     */
    public ?int $userId = null;

    // Static Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function displayName(): string
    {
        return Craft::t('password-policy', 'Notification log');
    }

    /**
     * @inheritdoc
     *
     * @return NotificationLogQuery
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function find(): NotificationLogQuery
    {
        return new NotificationLogQuery(static::class);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function hasStatuses(): bool
    {
        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function isLocalized(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function lowerDisplayName(): string
    {
        return Craft::t('password-policy', 'notification log');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pluralDisplayName(): string
    {
        return Craft::t('password-policy', 'Notification log entries');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pluralLowerDisplayName(): string
    {
        return Craft::t('password-policy', 'notification log entries');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function refHandle(): ?string
    {
        return 'notificationLog';
    }

    /**
     * @inheritdoc
     *
     * Maps `NotificationStatus` cases onto the element-index status
     * filter. Used by `NotificationLogQuery::statusCondition()` to
     * translate a status key into SQL.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function statuses(): array
    {
        return [
            NotificationStatus::Sent->value => [
                'label' => NotificationStatus::Sent->label(),
                'color' => NotificationStatus::Sent->color(),
            ],
            NotificationStatus::Failed->value => [
                'label' => NotificationStatus::Failed->label(),
                'color' => NotificationStatus::Failed->color(),
            ],
        ];
    }

    // Protected Static Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineActions(string $source = null): array
    {
        return [
            ResendNotification::class,
            [
                'type' => Delete::class,
                'confirmationMessage' => Craft::t(
                    'password-policy',
                    'Are you sure you want to delete the selected notification log entries?',
                ),
                'successMessage' => Craft::t(
                    'password-policy',
                    'Notification log entries deleted.',
                ),
            ],
            [
                'type' => Restore::class,
                'successMessage' => Craft::t('password-policy', 'Notification log entries restored.'),
                'partialSuccessMessage' => Craft::t('password-policy', 'Some notification log entries restored.'),
                'failMessage' => Craft::t('password-policy', 'Notification log entries not restored.'),
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineDefaultTableAttributes(string $source): array
    {
        return [
            'notificationType',
            'recipientEmail',
            'subject',
            'sentAt',
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSearchableAttributes(): array
    {
        return ['recipientEmail', 'subject', 'errorMessage', 'notificationType'];
    }

    /**
     * @inheritdoc
     *
     * `All` + per-status sources. Per-notification-type sources are
     * out-of-scope for Step 4 — additive enhancement that can land
     * in 5.3 without breaking the current shape.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSources(string $context = null): array
    {
        return [
            [
                'key' => '*',
                'label' => Craft::t('password-policy', 'All notifications'),
                'criteria' => [],
                'defaultSort' => ['sentAt', 'desc'],
            ],
            ['heading' => Craft::t('password-policy', 'Status')],
            [
                'key' => 'status:sent',
                'label' => NotificationStatus::Sent->label(),
                'criteria' => ['status' => NotificationStatus::Sent->value],
                'defaultSort' => ['sentAt', 'desc'],
            ],
            [
                'key' => 'status:failed',
                'label' => NotificationStatus::Failed->label(),
                'criteria' => ['status' => NotificationStatus::Failed->value],
                'defaultSort' => ['sentAt', 'desc'],
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSortOptions(): array
    {
        return [
            [
                'label' => Craft::t('password-policy', 'Sent at'),
                'orderBy' => 'passwordpolicy_notification_log.sentAt',
                'attribute' => 'sentAt',
                'defaultDir' => 'desc',
            ],
            [
                'label' => Craft::t('password-policy', 'Type'),
                'orderBy' => 'passwordpolicy_notification_log.notificationType',
                'attribute' => 'notificationType',
            ],
            [
                'label' => Craft::t('password-policy', 'Status'),
                'orderBy' => 'passwordpolicy_notification_log.status',
                'attribute' => 'status',
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineTableAttributes(): array
    {
        return [
            'sentAt' => ['label' => Craft::t('password-policy', 'Sent at')],
            'notificationType' => ['label' => Craft::t('password-policy', 'Type')],
            'recipientEmail' => ['label' => Craft::t('password-policy', 'Recipient')],
            'subject' => ['label' => Craft::t('password-policy', 'Subject')],
            'userId' => ['label' => Craft::t('password-policy', 'User')],
            'siteIdValue' => ['label' => Craft::t('password-policy', 'Site')],
            'errorMessage' => ['label' => Craft::t('password-policy', 'Error')],
        ];
    }

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Element soft-delete + element restore (with the standard "Trashed"
     * source) are admin-only. Notification log rows are an audit
     * artefact; non-admin viewers (`pp:notification-templates-manage`
     * holders) can resend or view but cannot delete.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canDelete(User $user): bool
    {
        return $user->admin;
    }

    /**
     * @inheritdoc
     *
     * Element-index visibility tracks the read permission on the
     * Notifications → Activity surface. Pro-edition gating happens at
     * the CP subnav level; non-CP queries (Pest, console) skip it.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canView(User $user): bool
    {
        if ($user->admin) {
            return true;
        }

        return $user->can('pp:notification-templates-manage');
    }

    /**
     * @inheritdoc
     *
     * Notification log entries are append-only — written by
     * `NotificationService` on dispatch attempts. The element exists
     * to provide the queryable / indexable surface, not an editable
     * surface; CP "Save" actions are blocked here.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canSave(User $user): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     *
     * Persists the paired `NotificationLogRecord` after Craft has saved
     * the `craft_elements` row. Mirrors Formie's `SentNotification`
     * pattern — element id IS record id IS `craft_elements.id`.
     *
     * @throws Exception when the record is unexpectedly missing on an
     *     update (corruption indicator)
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function afterSave(bool $isNew): void
    {
        if ($isNew) {
            $record = new NotificationLogRecord();
            $record->id = (int)$this->id;
        } else {
            $record = NotificationLogRecord::findOne($this->id);

            if ($record === null) {
                throw new Exception('Invalid notification log id: ' . $this->id);
            }
        }

        $record->userId = $this->userId;
        $record->notificationType = $this->notificationType ?? '';
        $record->status = $this->status ?? NotificationStatus::Sent->value;
        $record->recipientEmail = $this->recipientEmail;
        $record->siteId = $this->siteIdValue;
        $record->subject = $this->subject;
        $record->body = $this->body;
        $record->errorMessage = $this->errorMessage;
        $record->resentFromId = $this->resentFromId;
        $record->sentAt = $this->sentAt !== null
            ? Db::prepareDateForDb($this->sentAt)
            : Db::prepareDateForDb(DateTimeHelper::now());

        $record->save(false);

        parent::afterSave($isNew);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStatus(): ?string
    {
        return $this->status;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUiLabel(): string
    {
        // The activity index displays the rendered subject as the row's
        // chip label. Fall back to a type-prefixed sentAt stamp on rows
        // without a captured subject (mailer-key sources).
        if ($this->subject !== null && $this->subject !== '') {
            return $this->subject;
        }

        $type = $this->notificationType ?? Craft::t('password-policy', 'notification');
        $date = $this->sentAt?->format('Y-m-d H:i') ?? '';

        return trim("{$type}, {$date}");
    }

    /**
     * Returns true when the row's type is resendable. Editable-template
     * sources (`expiry_reminder`, `breach_detected`) re-render fresh;
     * mailer-key sources (`new_device`, `admin_alert_*`) need the
     * original event payload that the log doesn't snapshot.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isResendable(): bool
    {
        return in_array($this->notificationType, ['expiry_reminder', 'breach_detected'], true);
    }

    /**
     * Returns the HTML for this row's status pill — the same shape
     * `attributeHtml('status')` renders on the element index. Exposed
     * for the per-detail view + the per-user panel so they don't
     * hand-roll `<span class="status-label">` markup that drifts from
     * the index over time.
     *
     * Falls back to `Html::encode($this->status)` when the raw string
     * doesn't map to a known `NotificationStatus` case — defensive for
     * any future status value not yet covered by the enum.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStatusLabelHtml(): string
    {
        if ($this->status === null) {
            return '';
        }

        $statusCase = NotificationStatus::tryFrom($this->status);

        if ($statusCase === null) {
            return Html::encode($this->status);
        }

        return (string)Cp::statusLabelHtml([
            'color' => $statusCase->color(),
            'label' => $statusCase->label(),
        ]);
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function attributeHtml(string $attribute): string
    {
        switch ($attribute) {
            case 'sentAt':
                if ($this->sentAt === null) {
                    return '';
                }

                $href = UrlHelper::cpUrl('password-policy/notifications/activity/' . $this->id);

                return Html::a(
                    Craft::$app->getFormatter()->asDatetime($this->sentAt, 'short'),
                    $href,
                );

            case 'status':
                // Routes through `getStatusLabelHtml()` so the index
                // pill and the detail / per-user panel pills stay
                // in lockstep — same `Cp::statusLabelHtml()` call.
                return $this->getStatusLabelHtml();

            case 'notificationType':
                if ($this->notificationType === null) {
                    return '';
                }

                return Html::tag('code', Html::encode($this->notificationType));

            case 'recipientEmail':
                return $this->recipientEmail !== null
                    ? Html::encode($this->recipientEmail)
                    : '';

            case 'subject':
                if ($this->subject === null || $this->subject === '') {
                    return '';
                }

                $truncated = strlen($this->subject) > 80
                    ? substr($this->subject, 0, 80) . '…'
                    : $this->subject;

                return Html::tag('span', Html::encode($truncated), [
                    'title' => $this->subject,
                ]);

            case 'userId':
                if ($this->userId === null) {
                    return '';
                }

                $user = Craft::$app->getUsers()->getUserById($this->userId);

                return $user !== null ? Cp::elementChipHtml($user) : '';

            case 'siteIdValue':
                if ($this->siteIdValue === null) {
                    return '';
                }

                $site = Craft::$app->getSites()->getSiteById($this->siteIdValue);

                return $site !== null ? Html::encode($site->getName()) : '';

            case 'errorMessage':
                if ($this->errorMessage === null || $this->errorMessage === '') {
                    return '';
                }

                $truncated = strlen($this->errorMessage) > 80
                    ? substr($this->errorMessage, 0, 80) . '…'
                    : $this->errorMessage;

                return Html::tag('span', Html::encode($truncated), [
                    'class' => 'error',
                    'title' => $this->errorMessage,
                ]);
        }

        return parent::attributeHtml($attribute);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function cpEditUrl(): ?string
    {
        return UrlHelper::cpUrl('password-policy/notifications/activity/' . $this->id);
    }
}
