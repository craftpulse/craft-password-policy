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

use Craft;
use craft\base\Model;
use craft\enums\Color;
use craft\helpers\Cp;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;
use DateTime;
use Throwable;
use yii\validators\UrlValidator;

/**
 * Class WebhookEndpointModel
 *
 * Validation + transport model for a row in
 * `passwordpolicy_webhook_endpoints` (G9). Pairs with
 * {@see WebhookEndpointRecord} — the controller hydrates the model
 * from POST, validates, then `WebhookService::saveEndpoint()` mirrors
 * the surviving fields onto a record.
 *
 * Encryption boundary
 * -------------------
 * `secretCurrent` and `secretPrevious` are encrypted at rest via
 * `Craft::$app->getSecurity()->encryptByKey()`. The boundary is THIS
 * model — the record stores opaque ciphertext, the model surface holds
 * plaintext for use by `WebhookService::dispatch()` (HMAC signing) and
 * for the once-and-only-once display in CP after creation/rotation.
 *
 *  - `fromRecord()` decrypts both columns when hydrating.
 *  - `toRecordAttributes()` encrypts both columns when persisting.
 *  - The plaintext NEVER round-trips through the DB.
 *
 * Craft's `encryptByKey()` (no key arg) uses the install's `securityKey`
 * from general.php — that's the right primitive. Don't introduce a
 * per-plugin key.
 *
 * Datetime columns come back from ActiveRecord as raw strings;
 * `fromRecord()` hydrates them via `DateTimeHelper::toDateTime()` per
 * the project idiom (direct assignment to `?DateTime` properties throws
 * on a string).
 *
 * Edition: every — the model class itself is edition-independent
 * (capture is universal). The controller / subnav / queue job that
 * consume the model are Enterprise-gated.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookEndpointModel extends Model
{
    // Static Methods
    // =========================================================================

    /**
     * Hydrates a `WebhookEndpointModel` from an ActiveRecord row.
     *
     * Decrypts `secretCurrent` and `secretPrevious` at this boundary so
     * the model surface always exposes plaintext for use by the service
     * layer. A decrypt failure (corrupted ciphertext, rotated security
     * key) leaves the field `null` so callers can detect the gap; the
     * service treats a missing `secretCurrent` as an unsignable endpoint.
     *
     * Datetime columns come back from ActiveRecord as raw strings.
     * Routing them through `DateTimeHelper::toDateTime()` produces a
     * `?DateTime` matching the typed property — direct assignment of a
     * string to a `?DateTime` property throws.
     *
     * @param WebhookEndpointRecord $record
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRecord(WebhookEndpointRecord $record): self
    {
        $model = new self();
        $model->id = (int)$record->id;
        $model->name = $record->name;
        $model->url = (string)$record->url;
        $model->secretCurrent = self::_decryptOrNull((string)$record->secretCurrent);
        $model->secretPrevious = $record->secretPrevious !== null && $record->secretPrevious !== ''
            ? self::_decryptOrNull((string)$record->secretPrevious)
            : null;
        $model->secretRotatedAt = $record->secretRotatedAt !== null
            ? DateTimeHelper::toDateTime($record->secretRotatedAt) ?: null
            : null;
        $model->eventClasses = is_array($record->eventClasses) ? $record->eventClasses : null;
        $model->enabled = (bool)$record->enabled;
        $model->lastDeliveredRowId = $record->lastDeliveredRowId !== null
            ? (int)$record->lastDeliveredRowId
            : null;
        $model->consecutiveFailures = (int)$record->consecutiveFailures;
        $model->circuitOpenAt = $record->circuitOpenAt !== null
            ? DateTimeHelper::toDateTime($record->circuitOpenAt) ?: null
            : null;
        $model->dateCreated = DateTimeHelper::toDateTime($record->dateCreated) ?: null;
        $model->dateUpdated = DateTimeHelper::toDateTime($record->dateUpdated) ?: null;
        $model->uid = (string)$record->uid;

        return $model;
    }

    // Public Properties
    // =========================================================================

    /**
     * @var \DateTime|null UTC timestamp the circuit opened. Null when
     *     the circuit is closed. Populated by `WebhookService` when the
     *     consecutive-failure threshold trips; cleared on successful
     *     delivery.
     */
    public ?DateTime $circuitOpenAt = null;

    /**
     * @var int durable mirror of the cache-resident consecutive-failure
     *     counter. Survives cache flushes so circuit state is anchored
     *     in the DB. Reset to 0 on a successful delivery.
     */
    public int $consecutiveFailures = 0;

    /**
     * @var \DateTime|null
     */
    public ?DateTime $dateCreated = null;

    /**
     * @var \DateTime|null
     */
    public ?DateTime $dateUpdated = null;

    /**
     * @var bool whether the endpoint is enabled. Disabled endpoints are
     *     skipped by the queue job entirely — distinct from circuit-
     *     open, which is automatic and self-recovering.
     */
    public bool $enabled = true;

    /**
     * @var array<int, string>|null per-endpoint event-class allowlist
     *     override. Null or empty = use the global
     *     `webhookForwardEventClasses` setting. Stored as a JSON
     *     column; the model surface accepts a list of strings.
     */
    public ?array $eventClasses = null;

    /**
     * @var int|null the endpoint ID; null for new records.
     */
    public ?int $id = null;

    /**
     * @var int|null per-endpoint dispatch watermark — the highest
     *     audit-log row id this endpoint has accepted. The job
     *     dispatches rows where `id > lastDeliveredRowId`; null on a
     *     fresh endpoint means "deliver from the next row forward."
     *     Endpoints created mid-stream don't backfill historical rows
     *     — that's a 5.3 enhancement.
     */
    public ?int $lastDeliveredRowId = null;

    /**
     * @var string|null admin-supplied display label. Optional — when
     *     null, the index falls back to the URL.
     */
    public ?string $name = null;

    /**
     * @var string|null the active HMAC signing secret in plaintext. The
     *     persistence layer encrypts on save; the model surface holds
     *     plaintext only between `fromRecord()` decrypt and
     *     `toRecordAttributes()` encrypt. Never log this value. Never
     *     re-render in edit forms.
     */
    public ?string $secretCurrent = null;

    /**
     * @var string|null the prior HMAC signing secret in plaintext,
     *     valid during the rotation grace window. Same encryption +
     *     never-log contract as `secretCurrent`. Null when no rotation
     *     is active or after `RotateWebhookSecretJob` reaped it.
     */
    public ?string $secretPrevious = null;

    /**
     * @var \DateTime|null UTC timestamp the most recent rotation
     *     happened. Drives the grace-window expiry that nulls
     *     `secretPrevious`.
     */
    public ?DateTime $secretRotatedAt = null;

    /**
     * @var string|null
     */
    public ?string $uid = null;

    /**
     * @var string the webhook endpoint URL. Resolved at use via
     *     `App::parseEnv()` so operators can reference an env variable
     *     (e.g. `$PP_WEBHOOK_URL`) here. Required.
     */
    public string $url = '';

    // Public Methods
    // =========================================================================

    /**
     * Returns the persistence-shape attributes for the record layer.
     * Encrypts `secretCurrent` and `secretPrevious` at the boundary so
     * the DB never sees plaintext. Returns the array the
     * service can `array_merge` onto a record before saving.
     *
     * The encryption envelope is Craft's `Security::encryptByKey()` —
     * no key arg means Craft uses the install's `securityKey` from
     * `config/general.php`. Don't introduce a per-plugin key.
     *
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function toRecordAttributes(): array
    {
        return [
            'name' => $this->name,
            'url' => $this->url,
            'secretCurrent' => $this->secretCurrent !== null && $this->secretCurrent !== ''
                ? self::_encryptForStorage($this->secretCurrent)
                : '',
            'secretPrevious' => $this->secretPrevious !== null && $this->secretPrevious !== ''
                ? self::_encryptForStorage($this->secretPrevious)
                : null,
            'secretRotatedAt' => $this->secretRotatedAt?->format('Y-m-d H:i:s'),
            'eventClasses' => !empty($this->eventClasses)
                ? array_values($this->eventClasses)
                : null,
            'enabled' => $this->enabled,
            'lastDeliveredRowId' => $this->lastDeliveredRowId,
            'consecutiveFailures' => $this->consecutiveFailures,
            'circuitOpenAt' => $this->circuitOpenAt?->format('Y-m-d H:i:s'),
        ];
    }

    /**
     * Returns the HTML for this endpoint's "Enabled" status pill —
     * green when enabled, gray when disabled. Routes through
     * `Cp::statusLabelHtml()` so the pill matches Craft's native
     * Status column shape (introduced in CMS 5.2.0).
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEnabledLabelHtml(): string
    {
        return (string)Cp::statusLabelHtml([
            'color' => $this->enabled ? Color::Green : Color::Gray,
            'label' => $this->enabled
                ? Craft::t('app', 'Enabled')
                : Craft::t('app', 'Disabled'),
        ]);
    }

    /**
     * Returns the HTML for this endpoint's circuit-breaker status
     * pill — green when closed, red when open. The open variant
     * includes the consecutive-failure count inline so operators
     * see severity at a glance from the index.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getCircuitLabelHtml(): string
    {
        if ($this->circuitOpenAt === null) {
            return (string)Cp::statusLabelHtml([
                'color' => Color::Green,
                'label' => Craft::t('password-policy', 'Closed'),
            ]);
        }

        return (string)Cp::statusLabelHtml([
            'color' => Color::Red,
            'label' => Craft::t(
                'password-policy',
                'Open ({n} {n, plural, =1{failure} other{failures}})',
                ['n' => $this->consecutiveFailures],
            ),
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
    protected function defineRules(): array
    {
        return array_merge(parent::defineRules(), [
            [['url'], 'required'],
            [['url'], 'string', 'max' => 2048],
            // URL validator runs against the post-env-parse string. We
            // accept literal env-var references too (e.g.
            // `$PP_WEBHOOK_URL`) — those start with `$` and skip URL
            // validation; resolution happens at dispatch time.
            [
                ['url'],
                UrlValidator::class,
                'defaultScheme' => 'https',
                'when' => fn(WebhookEndpointModel $model): bool => !str_starts_with($model->url, '$'),
                'message' => Craft::t(
                    'password-policy',
                    'The webhook URL must be a valid http(s) URL or an env-var reference (e.g. $PP_WEBHOOK_URL).',
                ),
            ],
            [['name'], 'string', 'max' => 255],
            [['enabled'], 'boolean'],
            [['consecutiveFailures'], 'integer', 'min' => 0],
            [['lastDeliveredRowId'], 'integer', 'min' => 0],
            [
                ['eventClasses'],
                'each',
                'rule' => ['string', 'max' => 128],
                'message' => Craft::t(
                    'password-policy',
                    'Each event class must be a string up to 128 characters.',
                ),
            ],
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Attempts to decrypt a base64-wrapped ciphertext blob via Craft's
     * `Security::decryptByKey()`. Returns null on a decrypt failure —
     * the caller (model hydration) treats null as "unusable secret"
     * and the service refuses to dispatch against an endpoint with a
     * null `secretCurrent`. This preserves the failure-mode contract:
     * corrupted ciphertext or a rotated `securityKey` doesn't crash
     * the queue worker; the endpoint visibly degrades.
     *
     * The base64 wrap is needed because Craft's `encryptByKey` returns
     * raw binary bytes (HKDF + AES + HMAC envelope). MySQL `text`
     * columns are utf8mb4 by default and reject sequences that aren't
     * valid UTF-8. Wrapping in base64 keeps the column ASCII-clean
     * across MySQL/PostgreSQL/SQLite.
     *
     * @param string $cipher base64-encoded ciphertext from the DB
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _decryptOrNull(string $cipher): ?string
    {
        if ($cipher === '') {
            return null;
        }

        $raw = base64_decode($cipher, true);
        if ($raw === false) {
            Craft::warning(
                'Webhook endpoint secret is not valid base64; cannot decrypt.',
                'password-policy',
            );

            return null;
        }

        try {
            $decrypted = Craft::$app->getSecurity()->decryptByKey($raw);
        } catch (Throwable $e) {
            Craft::warning(
                'Failed to decrypt webhook endpoint secret: ' . $e->getMessage(),
                'password-policy',
            );

            return null;
        }

        return $decrypted !== false ? $decrypted : null;
    }

    /**
     * Encrypts plaintext via Craft's `Security::encryptByKey()` and
     * wraps the binary output in base64 so it stores cleanly in a
     * utf8mb4 `text` column. Pairs with `_decryptOrNull()` on the
     * read side.
     *
     * @param string $plaintext
     * @return string base64-encoded ciphertext suitable for DB storage
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _encryptForStorage(string $plaintext): string
    {
        return base64_encode(
            Craft::$app->getSecurity()->encryptByKey($plaintext),
        );
    }
}
