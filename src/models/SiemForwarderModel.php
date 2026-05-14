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
use craftpulse\passwordpolicy\records\SiemForwarderRecord;
use DateTime;

/**
 * Class SiemForwarderModel
 *
 * Validation + transport model for a row in
 * `passwordpolicy_siem_forwarders`. Pairs with
 * {@see SiemForwarderRecord} — the controller hydrates the model from
 * POST, validates, then `SiemService::saveForwarder()` mirrors the
 * surviving fields onto a record. Datetime columns come back from
 * ActiveRecord as raw strings; `fromRecord()` hydrates them via
 * `DateTimeHelper::toDateTime()` per the project idiom (direct assignment
 * to `?DateTime` properties throws on a string).
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
     * The default port used for syslog-over-TLS endpoints (RFC 5425
     * registered IANA port). New-forwarder forms pre-fill this.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const DEFAULT_SYSLOG_TLS_PORT = 6514;

    /**
     * The single supported protocol value in 5.2.0. UDP cut from the
     * matrix entirely (unreliable for audit forwarding); webhook ships
     * separately as G9. Future syslog variants (e.g. `syslog-tcp`) join
     * here without a schema migration — the column is a string.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const PROTOCOL_SYSLOG_TLS = 'syslog-tls';

    // Static Methods
    // =========================================================================

    /**
     * Hydrates a `SiemForwarderModel` from an ActiveRecord row.
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
        $model->host = (string)$record->host;
        $model->port = (int)$record->port;
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
     * @var string the destination host. Required.
     */
    public string $host = '';

    /**
     * @var int|null the forwarder ID; null for new records.
     */
    public ?int $id = null;

    /**
     * @var string|null admin-supplied display label. Optional — when
     *     null, the index falls back to "host:port".
     */
    public ?string $name = null;

    /**
     * @var int the destination port. Defaults to RFC 5425 / IANA
     *     registered syslog-over-TLS port (6514).
     */
    public int $port = self::DEFAULT_SYSLOG_TLS_PORT;

    /**
     * @var string the forwarder protocol. Only `'syslog-tls'` is
     *     supported in 5.2.0.
     */
    public string $protocol = self::PROTOCOL_SYSLOG_TLS;

    /**
     * @var string|null env-var-resolved CA bundle path. Resolved at
     *     use via `App::parseEnv()` — operators store the literal
     *     env reference (e.g. `$PP_SIEM_CA_BUNDLE`) here.
     */
    public ?string $tlsCaBundlePath = null;

    /**
     * @var bool whether to verify the destination's TLS certificate
     *     chain. Defaults true; opt-out is per-forwarder for
     *     self-signed CA setups.
     */
    public bool $tlsCertVerify = true;

    /**
     * @var string|null
     */
    public ?string $uid = null;

    // Public Methods
    // =========================================================================

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
            [['host'], 'required'],
            [['host'], 'string', 'max' => 255],
            [['name', 'tlsCaBundlePath'], 'string', 'max' => 255],
            [['port'], 'required'],
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
                ['protocol'],
                'in',
                'range' => [self::PROTOCOL_SYSLOG_TLS],
                'message' => Craft::t(
                    'password-policy',
                    'The forwarder protocol is invalid.',
                ),
            ],
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
