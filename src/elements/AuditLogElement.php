<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
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
use craftpulse\passwordpolicy\elements\db\AuditLogQuery;
use craftpulse\passwordpolicy\records\AuditLogRecord;
use DateTime;
use Exception;

/**
 * Class AuditLogElement
 *
 * Craft element wrapper around `passwordpolicy_audit_log`. Pairs with
 * {@see AuditLogRecord}: the element provides the queryable + index
 * surface, the record stays the storage layer. Element id IS record id
 * IS `craft_elements.id`.
 *
 * **Chain invariants preserved across the refactor.** The hash chain
 * canonicalize() input is the audit_log row's columns only — the
 * paired craft_elements row is element-layer metadata that does NOT
 * enter the hash. Every existing chain hash continues to verify
 * byte-identically before and after the element-ification (Step 5).
 * The verifier (`password-policy/audit/verify`) reads raw rows via
 * `Query` cursor and recomputes; the element layer is purely additive
 * for the CP index + future G3 dashboard.
 *
 * **Capture is universal — exposure is edition-gated.** The chain
 * runs on every edition (Lite included). The Pro-only / Enterprise
 * compliance-dashboard subnav renders this element's index for
 * inspection; Lite installs still write the chain rows but can't
 * navigate to them via the CP. See `project_audit_capture_principle.md`.
 *
 * **Append-only.** Audit rows are written by `AuditLogService::logEvent()`
 * inside the chain-write critical section (SELECT ... FOR UPDATE on the
 * previous tail rowHash). The element exists for the queryable surface,
 * not an editable one — `canSave()` returns `false`.
 *
 * **Retention purge — hard delete.** Per L3 of the Step 5 invariants,
 * retention purge bypasses element soft-delete (dateDeleted) and hard-
 * deletes via a bulk `DELETE FROM craft_elements WHERE id IN (...)`
 * (FK CASCADE drops the audit_log row). Audit retention is a
 * compliance requirement — soft-delete UX would leave rows on disk
 * past the retention boundary. Bulk-deleting via raw SQL avoids the
 * per-row ElementHelper lifecycle event firing that
 * `deleteElementById($id, hardDelete: true)` would trigger on every
 * pruned row.
 *
 * **userId outlives the user.** Nullable + `SET NULL` on user hard-
 * delete so the audit row outlives the entity. `changedByUserId`
 * follows the same pattern.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditLogElement extends Element
{
    // Public Properties
    // =========================================================================

    /**
     * @var ?string HMAC-SHA-256 of the actor's email — the immutable
     *     mirror of `changedByUserId`. THIS is what the canonical hash
     *     payload hashes for the actor, not the mutable FK int (which is
     *     `SET NULL` on user delete). NULL when there was no actor, or
     *     the actor was already gone / had no email at write time.
     *
     * @since 5.2.0
     */
    public ?string $changedByIdentifier = null;

    /**
     * @var ?int admin / actor user-id who triggered the event when the
     *     event was an admin-on-behalf-of-user action. Nullable —
     *     self-service flows (user-initiated password change) leave it
     *     null. `SET NULL` on user hard-delete so the audit row outlives
     *     the entity. Persisted for joins / display, but EXCLUDED from
     *     the canonical hash payload — `changedByIdentifier` is the
     *     hashed actor identity.
     */
    public ?int $changedByUserId = null;

    /**
     * @var array<string, mixed>|string|null structured payload filtered
     *     through the per-event allowlist
     *     (`AuditLogService::ALLOWED_DETAILS_BY_EVENT`). Keys outside
     *     the event's allowlist are stripped at write time. Stored as
     *     a JSON column — Yii's MySQL driver typically returns an
     *     already-decoded array, but the element-pipeline population
     *     path does not invoke `phpTypecast()`, so `init()` normalises
     *     a leftover JSON string to array.
     */
    public array|string|null $details = null;

    /**
     * @var ?string event machine-key — every value MUST appear as a key
     *     in `AuditLogService::ALLOWED_DETAILS_BY_EVENT`. Fail-closed at
     *     the service: an unregistered event class drops the row and
     *     warns.
     */
    public ?string $event = null;

    /**
     * @var int number of SIEM forwarder attempts for this row. Bumped
     *     atomically by `SiemForwardJob::_recordRowOutcome()` when no
     *     forwarder accepts the row; reset implicitly on `forwardedAt`
     *     write.
     */
    public int $forwardAttempts = 0;

    /**
     * @var DateTime|string|null timestamp at which a SIEM forwarder
     *     successfully accepted this row. NULL = unforwarded. Consumed
     *     by the G8 SIEM forwarder's batch query. Element-pipeline
     *     population assigns the raw string column value; `init()`
     *     normalises to a `DateTime` instance.
     */
    public DateTime|string|null $forwardedAt = null;

    /**
     * @var ?string ISO 3166-1 alpha-2 country code (e.g. `US`) resolved
     *     from the request IP via the bundled DB-IP Lite database
     *     (Feature 4). NULL when geolocation is disabled, the edition is
     *     not Enterprise, or the IP could not be resolved. EXCLUDED from
     *     the canonical hash-chain payload — post-insert enrichment, not
     *     a hashed field.
     */
    public ?string $geoCountry = null;

    /**
     * @var ?string subdivision / region name resolved from the request
     *     IP (Feature 4). Almost always NULL — the bundled DB-IP Lite
     *     database is country-level. EXCLUDED from the canonical hash-
     *     chain payload.
     */
    public ?string $geoRegion = null;

    /**
     * @var ?string HMAC-SHA-256 of the client IP for post-deletion
     *     correlation without storing the raw IP. Keyed via
     *     `AuditLogService::_resolveAuditPiiKey()` — rotating the
     *     dedicated `auditPiiKey` destroys correlation against new
     *     rows.
     */
    public ?string $ipHash = null;

    /**
     * @var string the row outcome — `success` or `failure`. Maps to the
     *     element-index status filter via {@see statuses()}.
     */
    public string $outcome = 'success';

    /**
     * @var ?string `rowHash` of the row immediately preceding this one
     *     in `id` order. The genesis row's value is sixty-four zero
     *     characters — the verifier's chain-start sentinel.
     */
    public ?string $previousHash = null;

    /**
     * @var ?string SHA-256 of `canonicalize(payload) . previousHash`.
     *     Bit-deterministic; verified by `password-policy/audit/verify`.
     */
    public ?string $rowHash = null;

    /**
     * @var ?string operation source context — `admin`, `self-service`,
     *     `cli`, etc. Detected by `AuditLogService::_detectSource()`
     *     when callers don't pass an explicit value.
     */
    public ?string $source = null;

    /**
     * @var ?string HMAC-SHA-256 of the affected user's email for post-
     *     deletion correlation. NULL when the user record has no email
     *     or was already hard-deleted at write time.
     */
    public ?string $userIdentifier = null;

    /**
     * @var ?int the user the event applies to. Nullable — system-level
     *     events (e.g. policy_changed by an admin) leave it null.
     *     `SET NULL` on user hard-delete so the audit row outlives the
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
        return Craft::t('password-policy', 'Audit log entry');
    }

    /**
     * @inheritdoc
     *
     * @return AuditLogQuery
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function find(): AuditLogQuery
    {
        return new AuditLogQuery(static::class);
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
        return Craft::t('password-policy', 'audit log entry');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pluralDisplayName(): string
    {
        return Craft::t('password-policy', 'Audit log');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pluralLowerDisplayName(): string
    {
        return Craft::t('password-policy', 'audit log');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function refHandle(): ?string
    {
        return 'auditLog';
    }

    /**
     * @inheritdoc
     *
     * Maps the row's `outcome` column onto the element-index status
     * filter. The query bridge lives in
     * {@see AuditLogQuery::statusCondition()}.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function statuses(): array
    {
        return [
            'success' => [
                'label' => Craft::t('password-policy', 'Success'),
                'color' => 'green',
            ],
            'failure' => [
                'label' => Craft::t('password-policy', 'Failure'),
                'color' => 'red',
            ],
        ];
    }

    // Protected Static Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Delete + Restore only. Per the Step 5 invariants (L3 + L4), the
     * verifier and forwarders read raw rows via `Query` cursor — the
     * element index intentionally does NOT expose a "Resend" / "Forward"
     * action. SIEM + webhook delivery is queue-driven by G8/G9.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineActions(string $source = null): array
    {
        return [
            [
                'type' => Delete::class,
                'confirmationMessage' => Craft::t(
                    'password-policy',
                    'Are you sure you want to delete the selected audit log entries? Audit retention is a compliance requirement, so only delete when you have an off-site archive.',
                ),
                'successMessage' => Craft::t(
                    'password-policy',
                    'Audit log entries deleted.',
                ),
            ],
            [
                'type' => Restore::class,
                'successMessage' => Craft::t('password-policy', 'Audit log entries restored.'),
                'partialSuccessMessage' => Craft::t('password-policy', 'Some audit log entries restored.'),
                'failMessage' => Craft::t('password-policy', 'Audit log entries not restored.'),
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
            'dateCreated',
            'event',
            'userId',
            'source',
            'outcome',
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
        return ['event', 'source', 'userIdentifier'];
    }

    /**
     * @inheritdoc
     *
     * `All` + per-outcome sources. Per-event-class sources are out-of-
     * scope for Step 5 — additive enhancement that G3 (compliance
     * dashboard) can layer on without breaking this shape.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSources(string $context = null): array
    {
        return [
            [
                'key' => '*',
                'label' => Craft::t('password-policy', 'All events'),
                'criteria' => [],
                'defaultSort' => ['dateCreated', 'desc'],
            ],
            ['heading' => Craft::t('password-policy', 'Outcome')],
            [
                'key' => 'outcome:success',
                'label' => Craft::t('password-policy', 'Success'),
                'criteria' => ['outcome' => 'success'],
                'defaultSort' => ['dateCreated', 'desc'],
            ],
            [
                'key' => 'outcome:failure',
                'label' => Craft::t('password-policy', 'Failure'),
                'criteria' => ['outcome' => 'failure'],
                'defaultSort' => ['dateCreated', 'desc'],
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
                'label' => Craft::t('password-policy', 'When'),
                'orderBy' => 'passwordpolicy_audit_log.dateCreated',
                'attribute' => 'dateCreated',
                'defaultDir' => 'desc',
            ],
            [
                'label' => Craft::t('password-policy', 'Event'),
                'orderBy' => 'passwordpolicy_audit_log.event',
                'attribute' => 'event',
            ],
            [
                'label' => Craft::t('password-policy', 'Outcome'),
                'orderBy' => 'passwordpolicy_audit_log.outcome',
                'attribute' => 'outcome',
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
            'dateCreated' => ['label' => Craft::t('password-policy', 'When')],
            'event' => ['label' => Craft::t('password-policy', 'Event')],
            'userId' => ['label' => Craft::t('password-policy', 'User')],
            'source' => ['label' => Craft::t('password-policy', 'Source')],
            'outcome' => ['label' => Craft::t('password-policy', 'Outcome')],
            'details' => ['label' => Craft::t('password-policy', 'Details')],
            'ipHash' => ['label' => Craft::t('password-policy', 'IP hash')],
        ];
    }

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Hydrates the `details` JSON column + `forwardedAt` datetime on
     * read. Yii's JSON ColumnSchema decodes JSON columns through
     * `phpTypecast()`, but the element-pipeline population path does
     * NOT route through that, so a leftover string occasionally
     * surfaces (driver-dependent). Normalise here to a stable shape so
     * downstream consumers (table-attribute renderer, allowlist
     * inspections, the future G3 dashboard) read predictable types.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function init(): void
    {
        parent::init();

        if (is_string($this->details)) {
            $decoded = json_decode($this->details, true);
            $this->details = is_array($decoded) ? $decoded : null;
        }

        if (is_string($this->forwardedAt)) {
            $this->forwardedAt = DateTimeHelper::toDateTime($this->forwardedAt) ?: null;
        }
    }

    /**
     * @inheritdoc
     *
     * Persists the paired `AuditLogRecord` after Craft has saved the
     * `craft_elements` row. Mirrors Step 4's `NotificationLogElement`
     * pattern — element id IS record id IS `craft_elements.id`.
     *
     * The chain-hash columns (`rowHash`, `previousHash`) are pre-
     * computed by `AuditLogService::logEvent()` inside its
     * `SELECT ... FOR UPDATE` critical section and assigned to the
     * element before save. They flow through to the paired record as-is
     * — this element does NOT recompute the chain.
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
            $record = new AuditLogRecord();
            $record->id = (int)$this->id;
        } else {
            $record = AuditLogRecord::findOne($this->id);

            if ($record === null) {
                throw new Exception('Invalid audit log id: ' . $this->id);
            }
        }

        $record->userId = $this->userId;
        $record->changedByUserId = $this->changedByUserId;
        $record->event = $this->event ?? '';
        $record->outcome = $this->outcome;
        $record->source = $this->source;
        // `details` is widened to `array|string|null` on the element to
        // accept either the raw JSON column value the element pipeline
        // populates with or the canonical-payload-shaped array the
        // service assigns. Either shape is fine to hand to the record —
        // Yii's JSON ColumnSchema serialises arrays on insert.
        $record->details = is_string($this->details)
            ? (json_decode($this->details, true) ?: null)
            : $this->details;
        $record->ipHash = $this->ipHash;
        $record->userIdentifier = $this->userIdentifier;
        $record->changedByIdentifier = $this->changedByIdentifier;
        $record->geoCountry = $this->geoCountry;
        $record->geoRegion = $this->geoRegion;
        $record->rowHash = $this->rowHash ?? '';
        $record->previousHash = $this->previousHash ?? '';
        $record->forwardedAt = $this->forwardedAt instanceof DateTime
            ? Db::prepareDateForDb($this->forwardedAt)
            : $this->forwardedAt;
        $record->forwardAttempts = $this->forwardAttempts;

        // The audit_log row's `dateCreated` + `uid` are the canonical-
        // payload values the chain SHA-256 hashes against. Per L1 of
        // the Step 5 invariants they must be byte-identical to what
        // the writer fed into `canonicalize()`. The element's
        // `dateCreated` + `uid` are set by the service BEFORE save
        // (inside the chain-write critical section), Craft's elements
        // table consumes them for the paired craft_elements row, and
        // we propagate the same values through to the audit_log
        // record here.
        if ($this->dateCreated !== null) {
            $record->dateCreated = Db::prepareDateForDb($this->dateCreated);
        }
        if ($this->uid !== null && $this->uid !== '') {
            $record->uid = $this->uid;
        }

        $record->save(false);

        parent::afterSave($isNew);
    }

    /**
     * @inheritdoc
     *
     * Admin-only delete. Even Enterprise non-admin viewers cannot
     * delete audit rows — compliance posture. Retention purge bypasses
     * this canDelete() entirely (server-side `purgeOldEntries()` hard-
     * deletes via `craft_elements`).
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
     * Audit rows are append-only. The element exists to provide the
     * queryable / indexable surface, not an editable one — CP "Save"
     * actions are blocked here.
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
     * Audit visibility tracks the read permission. Admins always see;
     * non-admin viewers need `pp:audit-view`. Edition gating (Pro /
     * Enterprise dashboard subnav) lives at the CP nav level — non-CP
     * queries (Pest, console, queue jobs) skip it.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canView(User $user): bool
    {
        if ($user->admin) {
            return true;
        }

        return $user->can('pp:audit-view');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStatus(): ?string
    {
        return $this->outcome;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUiLabel(): string
    {
        $event = $this->event ?? Craft::t('password-policy', 'event');
        $date = $this->dateCreated?->format('Y-m-d H:i') ?? '';

        return trim("{$event}, {$date}");
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
            case 'dateCreated':
                if ($this->dateCreated === null) {
                    return '';
                }

                return Html::encode(
                    Craft::$app->getFormatter()->asDatetime($this->dateCreated, 'short'),
                );

            case 'event':
                if ($this->event === null) {
                    return '';
                }

                return Html::tag('code', Html::encode($this->event));

            case 'outcome':
                $color = $this->outcome === 'success' ? 'green' : 'red';
                $label = $this->outcome === 'success'
                    ? Craft::t('password-policy', 'Success')
                    : Craft::t('password-policy', 'Failure');

                return Cp::statusLabelHtml([
                    'color' => $color,
                    'label' => $label,
                ]);

            case 'source':
                return $this->source !== null ? Html::encode($this->source) : '';

            case 'userId':
                if ($this->userId === null) {
                    return '';
                }

                $user = Craft::$app->getUsers()->getUserById($this->userId);

                return $user !== null ? Cp::elementChipHtml($user) : '';

            case 'details':
                if ($this->details === null || $this->details === []) {
                    return '';
                }

                $encoded = (string)json_encode($this->details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                $truncated = strlen($encoded) > 120
                    ? substr($encoded, 0, 120) . '…'
                    : $encoded;

                return Html::tag('code', Html::encode($truncated), [
                    'title' => $encoded,
                ]);

            case 'ipHash':
                if ($this->ipHash === null || $this->ipHash === '') {
                    return '';
                }

                // Show only the leading 8 chars — the full HMAC is privacy-
                // sensitive correlation material. The truncated prefix is
                // operationally useful (group rows by IP) without leaking
                // the full hash in CP screenshots.
                return Html::tag('code', Html::encode(substr($this->ipHash, 0, 8) . '…'), [
                    'title' => Craft::t('password-policy', 'Full HMAC truncated for display'),
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
        // No per-row CP edit screen lands in Step 5 — G3 (compliance
        // dashboard) owns the audit-log CP UI surface. Return null so
        // `Cp::elementChipHtml()` renders a chip without an action link.
        return null;
    }
}
