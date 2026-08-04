<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use Craft;
use craft\base\Model;
use craft\enums\Color;
use craft\helpers\Cp;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\helpers\EncryptedAttributeHelper;
use craftpulse\passwordpolicy\records\SiemForwarderRecord;
use DateTime;
use yii\validators\UrlValidator;

/**
 * Class SiemForwarderModel
 *
 * Validation + transport model for a row in
 * `passwordpolicy_siem_forwarders`. Pairs with
 * {@see SiemForwarderRecord} — the controller hydrates the model from
 * POST, validates, then `SiemService::saveForwarder()` mirrors the
 * surviving fields onto a record.
 *
 * Two destinations, one row shape
 * ------------------------------
 * `protocol` decides which half of the row is in use, and validation
 * follows it:
 *
 *  - `syslog-tls` requires `host` + `port`, and carries `framing` plus
 *    the two `tls*` columns. This is the transport for a self-hosted
 *    collector.
 *  - `http` requires an https `url`, and carries `authType`, the
 *    encrypted `authToken`, and the `headers` map. This is the transport
 *    for a collector that ingests over HTTPS.
 *
 * `toRecordAttributes()` nulls the other half on the way to the record,
 * so switching an existing forwarder from HTTP to syslog drops its
 * credential rather than leaving it encrypted-but-live in the row.
 *
 * Encryption boundary
 * -------------------
 * `authToken` is encrypted at rest via {@see EncryptedAttributeHelper},
 * the same boundary {@see WebhookEndpointModel} uses for its signing
 * secrets: `fromRecord()` decrypts, `toRecordAttributes()` encrypts, and
 * the plaintext never round-trips through the DB. `fields()` drops it
 * from the model's serialization surface so a save response can't echo
 * it back.
 *
 * Datetime columns come back from ActiveRecord as raw strings;
 * `fromRecord()` hydrates them via `DateTimeHelper::toDateTime()` per
 * the project idiom (direct assignment to `?DateTime` properties throws
 * on a string).
 *
 * Edition: every — the model class itself is edition-independent (capture
 * is universal). The controller / subnav / queue job that consume the
 * model are Enterprise-gated.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SiemForwarderModel extends Model
{
    // Const Properties
    // =========================================================================

    /**
     * HTTP Basic authentication. `authToken` holds the `user:password`
     * credential in plaintext on the model surface; the transport
     * base64-encodes it into the `Authorization` header.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const AUTH_TYPE_BASIC = 'basic';

    /**
     * HTTP Bearer authentication. `authToken` holds the token; the
     * transport sends `Authorization: Bearer <token>`.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const AUTH_TYPE_BEARER = 'bearer';

    /**
     * No `Authorization` header. The right choice for a collector that
     * authenticates by a token embedded in the URL, or by a vendor-named
     * header supplied through {@see $headers} (`DD-API-KEY`,
     * `Authorization: Splunk <token>`).
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const AUTH_TYPE_NONE = 'none';

    /**
     * The default port used for syslog-over-TLS endpoints (RFC 5425
     * registered IANA port). New-forwarder forms pre-fill this.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const DEFAULT_SYSLOG_TLS_PORT = 6514;

    /**
     * Header names an operator may not set through {@see $headers},
     * lowercased for comparison. `content-type` is fixed by the transport
     * (the body is always JSON) and the other three belong to the HTTP
     * client: letting a row override them produces a request Guzzle then
     * contradicts, which is a debugging trap rather than a feature.
     *
     * `authorization` is absent deliberately — it's rejected only when
     * `authType` would also write it, which the headers validator checks
     * separately.
     *
     * @var string[]
     *
     * @since 5.2.0
     */
    public const FORBIDDEN_HEADER_NAMES = [
        'connection',
        'content-length',
        'content-type',
        'host',
        'transfer-encoding',
    ];

    /**
     * Delimit each syslog message with a trailing newline. RFC 6587-style
     * non-transparent framing, which is what rsyslog's `imtcp` accepts by
     * default and what many self-hosted collectors are configured for.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const FRAMING_NEWLINE = 'newline';

    /**
     * Prefix each syslog message with its octet count and a space, per
     * RFC 5425 §4.3 (`MSG-LEN SP SYSLOG-MSG`). §4.3.1 makes reading that
     * length a MUST for a transport receiver, so this is the conformant
     * framing for port 6514 and the default for every forwarder.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const FRAMING_OCTET_COUNTED = 'octet-counted';

    /**
     * POST the canonical JSON of each audit row to an HTTPS collector.
     * Added in Gap A so a SIEM that only ingests over HTTPS is reachable
     * without the operator running a relay.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const PROTOCOL_HTTP = 'http';

    /**
     * Write an RFC 5424 message per audit row to a `tls://` stream
     * socket. UDP was cut from the matrix entirely (unreliable for audit
     * forwarding). Future syslog variants (e.g. `syslog-tcp`) join the
     * range without a schema migration — the column is a string.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const PROTOCOL_SYSLOG_TLS = 'syslog-tls';

    /**
     * Label passed to {@see EncryptedAttributeHelper} so a decrypt
     * failure names the credential in the warning without logging its
     * value.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const TOKEN_LABEL = 'SIEM forwarder auth token';

    // Static Methods
    // =========================================================================

    /**
     * Hydrates a `SiemForwarderModel` from an ActiveRecord row.
     *
     * Decrypts `authToken` at this boundary so the model surface always
     * exposes plaintext for the transport. A decrypt failure (corrupted
     * ciphertext, rotated security key) leaves the field null, and the
     * transport then refuses to send rather than authenticating with a
     * broken credential.
     *
     * Datetime columns come back from ActiveRecord as raw strings.
     * Routing them through `DateTimeHelper::toDateTime()` produces a
     * `?DateTime` matching the typed property — direct assignment of a
     * string to a `?DateTime` property throws.
     *
     * @param SiemForwarderRecord $record
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRecord(SiemForwarderRecord $record): self
    {
        $model = new self();
        $model->id = (int)$record->id;
        $model->name = $record->name;
        $model->protocol = (string)$record->protocol;
        $model->host = $record->host !== null ? (string)$record->host : null;
        $model->port = $record->port !== null ? (int)$record->port : null;
        $model->url = $record->url !== null ? (string)$record->url : null;
        $model->authType = $record->authType !== null && $record->authType !== ''
            ? (string)$record->authType
            : self::AUTH_TYPE_NONE;
        $model->authToken = $record->authToken !== null && $record->authToken !== ''
            ? EncryptedAttributeHelper::decryptOrNull((string)$record->authToken, self::TOKEN_LABEL)
            : null;
        $model->headers = is_array($record->headers) ? $record->headers : null;
        $model->framing = $record->framing !== null && $record->framing !== ''
            ? (string)$record->framing
            : self::FRAMING_OCTET_COUNTED;
        $model->tlsCertVerify = (bool)$record->tlsCertVerify;
        $model->tlsCaBundlePath = $record->tlsCaBundlePath;
        $model->eventClasses = is_array($record->eventClasses) ? $record->eventClasses : null;
        $model->enabled = (bool)$record->enabled;
        $model->circuitOpenAt = $record->circuitOpenAt !== null
            ? DateTimeHelper::toDateTime($record->circuitOpenAt) ?: null
            : null;
        $model->consecutiveFailures = (int)$record->consecutiveFailures;
        $model->dateCreated = DateTimeHelper::toDateTime($record->dateCreated) ?: null;
        $model->dateUpdated = DateTimeHelper::toDateTime($record->dateUpdated) ?: null;
        $model->uid = (string)$record->uid;

        return $model;
    }

    // Public Properties
    // =========================================================================

    /**
     * @var string|null the HTTP credential in plaintext, or an env-var
     *     reference (e.g. `$PP_SIEM_TOKEN`) resolved at forward time.
     *     Encrypted at rest either way. Meaningful only when `protocol`
     *     is `http` and `authType` is not `none`. Never log this value,
     *     and never re-render it in an edit form.
     */
    public ?string $authToken = null;

    /**
     * @var string how the HTTP transport authenticates: `none`,
     *     `bearer`, or `basic`. Ignored on the syslog transport, which
     *     authenticates by certificate.
     */
    public string $authType = self::AUTH_TYPE_NONE;

    /**
     * @var \DateTime|null UTC timestamp the circuit opened. Null when
     *     the circuit is closed. Populated by `SiemService` when the
     *     consecutive-failure threshold trips; cleared on successful
     *     forward.
     */
    public ?DateTime $circuitOpenAt = null;

    /**
     * @var int durable mirror of the cache-resident consecutive-failure
     *     counter. Survives cache flushes so circuit state is anchored
     *     in the DB. Reset to 0 on a successful forward.
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
     * @var bool whether the forwarder is enabled. Disabled forwarders
     *     are skipped by the queue job entirely — distinct from
     *     circuit-open, which is automatic and self-recovering.
     */
    public bool $enabled = true;

    /**
     * @var array<int, string>|null per-forwarder event-class allowlist
     *     override. Null or empty = use the global
     *     `siemForwardEventClasses` setting. Stored as a JSON column;
     *     the model surface accepts a list of strings.
     */
    public ?array $eventClasses = null;

    /**
     * @var string how the syslog transport delimits each message on the
     *     stream: `octet-counted` (RFC 5425 §4.3, the default and the
     *     conformant choice for port 6514) or `newline` (RFC 6587-style,
     *     what rsyslog's `imtcp` accepts by default). Ignored on the HTTP
     *     transport, which has no framing.
     */
    public string $framing = self::FRAMING_OCTET_COUNTED;

    /**
     * @var array<string, string>|null extra request headers for the HTTP
     *     transport, as a name => value map. Values support env-var
     *     references, resolved at forward time. Ignored on the syslog
     *     transport, which has no headers.
     */
    public ?array $headers = null;

    /**
     * @var string|null the destination host. Required on the syslog
     *     transport; null on the HTTP transport, which is addressed by
     *     `url`.
     */
    public ?string $host = null;

    /**
     * @var int|null the forwarder ID; null for new records.
     */
    public ?int $id = null;

    /**
     * @var string|null admin-supplied display label. Optional — when
     *     null, the index falls back to {@see getEndpointLabel()}.
     */
    public ?string $name = null;

    /**
     * @var int|null the destination port. Required on the syslog
     *     transport, where it defaults to the RFC 5425 / IANA registered
     *     syslog-over-TLS port (6514); null on the HTTP transport, which
     *     carries any non-default port in the URL.
     */
    public ?int $port = self::DEFAULT_SYSLOG_TLS_PORT;

    /**
     * @var string the forwarder protocol: `syslog-tls` or `http`.
     */
    public string $protocol = self::PROTOCOL_SYSLOG_TLS;

    /**
     * @var string|null env-var-resolved CA bundle path. Resolved at
     *     use via `App::parseEnv()` — operators store the literal
     *     env reference (e.g. `$PP_SIEM_CA_BUNDLE`) here. Honoured by
     *     both transports.
     */
    public ?string $tlsCaBundlePath = null;

    /**
     * @var bool whether to verify the destination's TLS certificate
     *     chain. Defaults true; opt-out is per-forwarder for
     *     self-signed CA setups, and applies to the syslog transport
     *     only. The HTTP transport always verifies, because it carries a
     *     credential.
     */
    public bool $tlsCertVerify = true;

    /**
     * @var string|null
     */
    public ?string $uid = null;

    /**
     * @var string|null the HTTPS collector URL for the HTTP transport.
     *     Resolved at use via `App::parseEnv()` so operators can store an
     *     env reference (e.g. `$PP_SIEM_URL`) here. Required on the HTTP
     *     transport; null on the syslog transport.
     */
    public ?string $url = null;

    // Public Methods
    // =========================================================================

    /**
     * Excludes the plaintext auth token from the model's default
     * serialization surface. `SiemForwarderController::actionSave`
     * returns `asModelSuccess($forwarder, …)`, which calls
     * `$model->toArray()` → `fields()`. Without this exclusion every
     * save of an HTTP forwarder would echo the decrypted credential
     * back in the JSON response body.
     *
     * @return array<int|string, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function fields(): array
    {
        $fields = parent::fields();
        unset($fields['authToken']);

        return $fields;
    }

    /**
     * Returns the label the CP shows for this forwarder: its name when
     * set, otherwise its endpoint. Keeps the index, the edit screen
     * title, and any log line naming a forwarder on one rule.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getDisplayName(): string
    {
        return $this->name ?: $this->getEndpointLabel();
    }

    /**
     * Returns the destination as a single string for display: the URL on
     * the HTTP transport, `host:port` on the syslog transport. Empty when
     * the forwarder has neither yet (an unsaved row on the new-forwarder
     * form).
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEndpointLabel(): string
    {
        if ($this->getIsHttp()) {
            return (string)$this->url;
        }

        if ($this->host === null || $this->host === '') {
            return '';
        }

        return sprintf('%s:%d', $this->host, (int)$this->port);
    }

    /**
     * Returns whether this forwarder uses the HTTP transport. Exposed as
     * `forwarder.isHttp` in Twig, where the edit screen toggles field
     * groups on it.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsHttp(): bool
    {
        return $this->protocol === self::PROTOCOL_HTTP;
    }

    /**
     * Returns whether this forwarder uses the syslog-over-TLS transport.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsSyslog(): bool
    {
        return $this->protocol === self::PROTOCOL_SYSLOG_TLS;
    }

    /**
     * Returns the HTML for this forwarder's "Enabled" status pill —
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
     * Returns the HTML for this forwarder's circuit-breaker status
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

    /**
     * Returns the persistence-shape attributes for the record layer.
     *
     * Two things happen here, both deliberate:
     *
     *  - `authToken` is encrypted, so the DB never sees the plaintext
     *    credential.
     *  - The unused half of the row is nulled per `protocol`. A forwarder
     *    switched from HTTP to syslog loses its URL, auth type, token,
     *    and headers in the same save that switches it, instead of
     *    keeping a live credential for a destination it no longer talks
     *    to.
     *
     * Circuit-breaker columns are absent on purpose. `SiemService`
     * updates `consecutiveFailures` / `circuitOpenAt` with targeted
     * writes from the forward path, and a CP save carrying whatever the
     * edit screen loaded would clobber a failure the sweep recorded in
     * between.
     *
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function toRecordAttributes(): array
    {
        $isHttp = $this->getIsHttp();
        $authType = $isHttp ? $this->authType : self::AUTH_TYPE_NONE;
        $hasToken = $authType !== self::AUTH_TYPE_NONE
            && $this->authToken !== null
            && $this->authToken !== '';

        return [
            'name' => $this->name,
            'protocol' => $this->protocol,
            'host' => $isHttp ? null : ($this->host ?: null),
            'port' => $isHttp ? null : $this->port,
            'url' => $isHttp ? ($this->url ?: null) : null,
            'authType' => $authType,
            'authToken' => $hasToken
                ? EncryptedAttributeHelper::encrypt((string)$this->authToken)
                : null,
            'headers' => $isHttp && !empty($this->headers) ? $this->headers : null,
            // Not nulled per protocol: the column is not null, and holding
            // the operator's choice through a round trip via HTTP means a
            // forwarder switched back to syslog still frames the way its
            // receiver expects.
            'framing' => $this->framing,
            'tlsCertVerify' => $this->tlsCertVerify,
            'tlsCaBundlePath' => $this->tlsCaBundlePath,
            'eventClasses' => !empty($this->eventClasses)
                ? array_values($this->eventClasses)
                : null,
            'enabled' => $this->enabled,
        ];
    }

    /**
     * Inline validator for the HTTP transport's custom header map.
     *
     * Rejects, per entry: a name that isn't an RFC 7230 field-name
     * token, an empty value, a name in
     * {@see FORBIDDEN_HEADER_NAMES}, and `Authorization` when `authType`
     * would write that header too (an operator who wants a vendor's own
     * `Authorization` scheme sets the auth type to `none`).
     *
     * @param string $attribute
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateHeaders(string $attribute): void
    {
        $headers = $this->headers;

        if ($headers === null || $headers === []) {
            return;
        }

        foreach ($headers as $name => $value) {
            $name = (string)$name;

            if (preg_match('/^[A-Za-z0-9!#$%&\'*+\-.^_`|~]+$/', $name) !== 1) {
                $this->addError($attribute, Craft::t(
                    'password-policy',
                    '"{name}" is not a valid header name.',
                    ['name' => $name],
                ));

                continue;
            }

            $lowerName = strtolower($name);

            if (in_array($lowerName, self::FORBIDDEN_HEADER_NAMES, true)) {
                $this->addError($attribute, Craft::t(
                    'password-policy',
                    'The {name} header is set by the forwarder and cannot be overridden.',
                    ['name' => $name],
                ));

                continue;
            }

            if ($lowerName === 'authorization' && $this->authType !== self::AUTH_TYPE_NONE) {
                $this->addError($attribute, Craft::t(
                    'password-policy',
                    'Set Authentication to "None" to send your own Authorization header.',
                ));

                continue;
            }

            if (!is_string($value) || trim($value) === '') {
                $this->addError($attribute, Craft::t(
                    'password-policy',
                    'The {name} header needs a value.',
                    ['name' => $name],
                ));
            }
        }
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
            [['name', 'tlsCaBundlePath'], 'string', 'max' => 255],
            [
                ['protocol'],
                'in',
                'range' => [self::PROTOCOL_SYSLOG_TLS, self::PROTOCOL_HTTP],
                'message' => Craft::t(
                    'password-policy',
                    'The forwarder protocol is invalid.',
                ),
            ],

            // Syslog transport — addressed by host + port.
            [
                ['host', 'port'],
                'required',
                'when' => fn(self $forwarder): bool => $forwarder->getIsSyslog(),
            ],
            [['host'], 'string', 'max' => 255],
            [
                ['port'],
                'integer',
                'min' => 1,
                'max' => 65535,
                'message' => Craft::t(
                    'password-policy',
                    'Port must be between 1 and 65535.',
                ),
            ],
            [
                ['framing'],
                'in',
                'range' => [self::FRAMING_OCTET_COUNTED, self::FRAMING_NEWLINE],
                'message' => Craft::t(
                    'password-policy',
                    'The message framing is invalid.',
                ),
            ],

            // HTTP transport — addressed by an https URL.
            [
                ['url'],
                'required',
                'when' => fn(self $forwarder): bool => $forwarder->getIsHttp(),
            ],
            [['url'], 'string', 'max' => 2048],
            // The URL validator runs on a literal URL only. An env-var
            // reference (e.g. `$PP_SIEM_URL`) starts with `$` and skips
            // it; `SiemService` re-checks the resolved scheme at forward
            // time, which is the only place that value exists.
            //
            // `validSchemes => ['https']` rejects an explicit `http://`
            // URL outright. The request carries pseudonymous audit rows
            // and, on most destinations, a credential — neither belongs
            // on a plaintext connection.
            [
                ['url'],
                UrlValidator::class,
                'defaultScheme' => 'https',
                'validSchemes' => ['https'],
                'when' => fn(self $forwarder): bool => $forwarder->getIsHttp()
                    && !str_starts_with((string)$forwarder->url, '$'),
                'message' => Craft::t(
                    'password-policy',
                    'The endpoint URL must be a valid https:// URL or an env-var reference (e.g. $PP_SIEM_URL).',
                ),
            ],
            [
                ['authType'],
                'in',
                'range' => [self::AUTH_TYPE_NONE, self::AUTH_TYPE_BEARER, self::AUTH_TYPE_BASIC],
                'message' => Craft::t(
                    'password-policy',
                    'The authentication type is invalid.',
                ),
            ],
            [
                ['authToken'],
                'required',
                'when' => fn(self $forwarder): bool => $forwarder->getIsHttp()
                    && $forwarder->authType !== self::AUTH_TYPE_NONE,
            ],
            [['authToken'], 'string', 'max' => 2048],
            [['headers'], 'validateHeaders'],

            [['tlsCertVerify', 'enabled'], 'boolean'],
            [['consecutiveFailures'], 'integer', 'min' => 0],
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
}
