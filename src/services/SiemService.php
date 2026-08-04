<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\helpers\App;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\SiemForwarderRecord;
use RuntimeException;
use Throwable;
use yii\base\Component;

/**
 * Class SiemService
 *
 * Forwards audit-log rows to one or more registered SIEM destinations.
 * Two transports, chosen per forwarder by its `protocol` column:
 *
 *  - `syslog-tls` writes an RFC 5424 message per row to a `tls://`
 *    stream socket, framed per the forwarder's `framing` column (RFC 5425
 *    octet counting by default). This reaches a self-hosted collector
 *    (rsyslog, syslog-ng, Graylog, QRadar, a Splunk indexer with a
 *    TCP-SSL input).
 *  - `http` POSTs the same canonical JSON to an HTTPS collector, with an
 *    optional `Authorization` header and an optional map of custom
 *    headers for vendor schemes. This reaches a SaaS collector that only
 *    ingests over HTTPS.
 *
 * Everything either side of the transport is shared: eligibility, the
 * circuit breaker, the never-throws contract, `sendTestEvent()`, and the
 * body itself. An unsupported `protocol` value (reachable only by direct
 * SQL — the CP and the model rule both refuse it) is a recorded failure
 * with a warning, never a misdelivery to the other transport.
 *
 * The HTTP transport is deliberately raw: the body is the canonical JSON
 * audit row and nothing else. A destination that needs a vendor envelope
 * around it (Splunk HEC's event wrapper, Datadog's array of log items)
 * needs that envelope built somewhere, and this service does not build
 * one. See `docs/user/features/siem-forwarders.md` for which
 * destinations that reaches.
 *
 * Architectural anchor: `project_audit_capture_principle.md`. Capture is
 * universal — every edition writes audit rows; the audit_log table ships
 * `forwardedAt` + `forwardAttempts` columns + index on every install
 * (Install.php). Exposure is gated — only Enterprise installs see the CP
 * subnav, can register forwarders, and run the queue job that consumes
 * them. The forwarders table exists empty on Lite / Pro and that's the
 * correct state. SIEM forwarding is the canonical example of "exposure
 * gated, capture universal."
 *
 * Failure mode contract: forwarder failures NEVER block the originating
 * audit/notification write. The forwarder is read-side only. `forward()`
 * never throws — it returns bool. The job's `processItem` is the only
 * place that can soft-fail per row, and a row left with `forwardedAt =
 * NULL` is naturally retriable on the next batch.
 *
 * Multi-forwarder semantics: a row is "forwarded" the moment ONE
 * forwarder accepts it. Operators with multiple endpoints get
 * at-least-once delivery to one of them; downstream SIEMs dedup on event
 * UID. Different intent (all-forwarders-must-succeed) is trivial to flip
 * — it's a single condition in `SiemForwardJob::processItem`.
 *
 * Circuit breaker (HIBP-style cache + DB durability):
 *
 *  - Cache key `pp:siem-forwarder-circuit:{forwarderId}` holds the
 *    consecutive-failure counter as a string. Cache `get()` returns
 *    `false` for missing keys (`feedback_skill_gaps.md` #11) so we use
 *    string sentinels and `cache->exists()` for presence checks.
 *  - `consecutiveFailures` + `circuitOpenAt` columns on
 *    `passwordpolicy_siem_forwarders` mirror the cache, so a flush
 *    doesn't reset circuit state.
 *  - Threshold (default 5) opens the circuit. `getActiveForwarders()`
 *    excludes opened forwarders within their cooldown window (default
 *    300s).
 *  - Half-open probe: a forwarder past its cooldown is included in the
 *    next batch — the next forward attempt IS the probe. On probe
 *    success, reset; on probe failure, push `circuitOpenAt` forward.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SiemService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Cache key prefix for the per-forwarder circuit-breaker counter.
     * Stable shape so cache-warming hits the same slot across processes.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const CACHE_KEY_CIRCUIT = 'pp:siem-forwarder-circuit:';

    /**
     * Maximum number of bytes read from a non-2xx response body when
     * building the operator-facing failure message on the HTTP transport.
     * The collector controls what it echoes back; this caps the read so a
     * hostile or chatty endpoint can't balloon the plugin log.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const ERROR_BODY_READ_LIMIT = 512;

    /**
     * Total Guzzle request timeout for the HTTP transport, in seconds.
     * Covers connect + TLS handshake + send + receive. A collector that
     * doesn't respond inside the window is a failure for circuit-breaker
     * purposes; the sweep retries the row on its next pass.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const HTTP_TIMEOUT_SECONDS = 10;

    /**
     * RFC 5424 syslog facility for "local0" — the conventional facility
     * for application-emitted audit events. Multiplied with severity to
     * produce the priority value that opens the syslog frame.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const SYSLOG_FACILITY_LOCAL0 = 16;

    /**
     * RFC 5424 syslog severity "notice" — the conventional severity for
     * audit-trail events that are operationally noteworthy but neither
     * warning nor error.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const SYSLOG_SEVERITY_NOTICE = 5;

    /**
     * Connect timeout for the TLS stream socket, in seconds. A SIEM
     * endpoint that doesn't accept inside 5s is effectively offline for
     * the purpose of an audit-forwarder retry; the queue job will pick
     * up the row on its next pass.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const TLS_CONNECT_TIMEOUT = 5;

    // Public Methods
    // =========================================================================

    /**
     * Deletes a forwarder by ID. No-op when the forwarder doesn't exist.
     * Returns true on a successful delete (or no-op), false on DB
     * failure.
     *
     * @param int $id
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function deleteForwarder(int $id): bool
    {
        try {
            Craft::$app->getDb()->createCommand()
                ->delete(SiemForwarderRecord::tableName(), ['id' => $id])
                ->execute();

            // Best-effort cache cleanup. The cache entry naturally
            // expires anyway, so a failure here is harmless.
            Craft::$app->getCache()->delete(self::CACHE_KEY_CIRCUIT . $id);
        } catch (Throwable $e) {
            Craft::error(
                'Failed to delete SIEM forwarder ' . $id . ': ' . $e->getMessage(),
                'password-policy',
            );

            return false;
        }

        return true;
    }

    /**
     * Sends `$auditRow` to `$forwarder` over whichever transport its
     * `protocol` names.
     *
     * Returns true when the destination accepted the row, false on any
     * failure (connect timeout, TLS handshake error, partial write, a
     * non-2xx HTTP response, a resolved URL that isn't https, an
     * unsupported protocol). NEVER throws — the failure-mode contract
     * requires that originating audit writes are decoupled from forwarder
     * health, and the only caller is the queue job's `processItem`, which
     * records the boolean outcome on the row.
     *
     * Updates the circuit-breaker state on every call:
     *
     *  - Success: resets the per-forwarder cache counter to 0 and
     *    clears `consecutiveFailures` + `circuitOpenAt` on the DB row
     *    (only when the prior state was non-zero — avoids a useless
     *    write on every successful forward).
     *  - Failure: increments cache + DB counter; opens the circuit
     *    (writes `circuitOpenAt = NOW()`) when the threshold is
     *    crossed.
     *
     * @param array<string, mixed> $auditRow the audit-log row to forward
     *     (raw row shape from the `passwordpolicy_audit_log` query — the
     *     full row, not just the canonical payload, so the consumer SIEM
     *     sees `id`, `rowHash`, `forwardedAt` if it cares to)
     * @param SiemForwarderModel $forwarder
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function forward(array $auditRow, SiemForwarderModel $forwarder): bool
    {
        if ($forwarder->id === null) {
            return false;
        }

        try {
            match ($forwarder->protocol) {
                SiemForwarderModel::PROTOCOL_HTTP => $this->_postToHttp($forwarder, $auditRow),
                SiemForwarderModel::PROTOCOL_SYSLOG_TLS => $this->_writeToSocket(
                    $forwarder,
                    $this->_buildSyslogFrame($auditRow),
                ),
                // Fail closed. Nothing else in the class branches on the
                // column, so without this an unrecognised value would take
                // whichever transport happened to be the fallback and
                // deliver an audit row somewhere the operator never
                // configured. A recorded failure plus the warning below is
                // the loud outcome instead.
                default => throw new RuntimeException(sprintf(
                    'Unsupported forwarder protocol "%s".',
                    $forwarder->protocol,
                )),
            };

            $this->_recordSuccess($forwarder);

            return true;
        } catch (Throwable $e) {
            // NEVER log the full request payload. Body of an audit row
            // can carry the (already-allowlist-filtered) `details` blob,
            // but a per-row error log every time the SIEM is unreachable
            // would dump that across the plugin log on every retry. The
            // diagnostic kept in the log is opaque: forwarder id +
            // exception message only.
            Craft::warning(
                'SIEM forward failed for forwarder ' . $forwarder->id . ': ' . $e->getMessage(),
                'password-policy',
            );
            $this->_recordFailure($forwarder);

            return false;
        }
    }

    /**
     * Returns the active forwarders eligible to receive an audit row
     * right now. "Active" means:
     *
     *  - `enabled = true`
     *  - circuit is closed (`circuitOpenAt IS NULL`), OR
     *  - circuit is open but past the cooldown window (half-open
     *    probe — next forward attempt IS the probe).
     *
     * The cooldown window is configurable via
     * `SettingsModel::$siemCircuitCooldownSeconds` (default 300s).
     *
     * @return array<int, SiemForwarderModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getActiveForwarders(): array
    {
        $cooldownSeconds = $this->_circuitCooldownSeconds();
        $cooldownThreshold = Carbon::now('UTC')
            ->subSeconds($cooldownSeconds)
            ->format('Y-m-d H:i:s');

        $rows = SiemForwarderRecord::find()
            ->where(['enabled' => true])
            ->andWhere([
                'or',
                ['circuitOpenAt' => null],
                ['<=', 'circuitOpenAt', $cooldownThreshold],
            ])
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var SiemForwarderRecord $row */
            $models[] = SiemForwarderModel::fromRecord($row);
        }

        return $models;
    }

    /**
     * Returns the event-class allowlist a forwarder consumes against.
     * Per-forwarder override wins when populated (non-null + non-empty);
     * otherwise the global `SettingsModel::$siemForwardEventClasses`
     * applies.
     *
     * The allowlist describes which TABLE STREAMS the forwarder pulls
     * from. For 5.2.0 only `audit_log` is supported. The setting shape
     * is forward-compatible — `notification_log` joins as a 5.3
     * expansion without a schema change.
     *
     * Per-event-name filtering on the audit `event` column (e.g. only
     * forward `password_changed`, not `account_locked`) is a 5.3
     * enhancement — the model supports the array shape now, the queue
     * job and CP UI don't drive that distinction.
     *
     * @param SiemForwarderModel $forwarder
     * @return array<int, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEligibleEventClasses(SiemForwarderModel $forwarder): array
    {
        if (!empty($forwarder->eventClasses)) {
            return array_values($forwarder->eventClasses);
        }

        return PasswordPolicy::$plugin->getSettings()->siemForwardEventClasses;
    }

    /**
     * Returns a single forwarder by ID, hydrated as a model. Returns
     * null when no row matches.
     *
     * @param int $id
     * @return SiemForwarderModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getForwarderById(int $id): ?SiemForwarderModel
    {
        /** @var SiemForwarderRecord|null $record */
        $record = SiemForwarderRecord::findOne(['id' => $id]);

        if ($record === null) {
            return null;
        }

        return SiemForwarderModel::fromRecord($record);
    }

    /**
     * Returns all configured forwarders ordered by ID (creation order).
     * Used by the CP index template; no edition gating here — the
     * controller / subnav are gated and that's where exposure stops.
     *
     * @return array<int, SiemForwarderModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function listForwarders(): array
    {
        $rows = SiemForwarderRecord::find()
            ->orderBy(['id' => SORT_ASC])
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var SiemForwarderRecord $row */
            $models[] = SiemForwarderModel::fromRecord($row);
        }

        return $models;
    }

    /**
     * Resets a forwarder's circuit state on demand — clears
     * `circuitOpenAt`, zeroes `consecutiveFailures`, and deletes the
     * cache counter. Surfaced as a CP button so an operator who fixed a
     * SIEM-side issue (firewall / cert / endpoint outage) doesn't have
     * to wait for the cooldown to elapse.
     *
     * No-op when the forwarder is already in clean state. Returns true
     * on a successful reset (or no-op), false on DB failure.
     *
     * @param int $id
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resetCircuit(int $id): bool
    {
        try {
            $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

            Craft::$app->getDb()->createCommand()
                ->update(
                    SiemForwarderRecord::tableName(),
                    [
                        'circuitOpenAt' => null,
                        'consecutiveFailures' => 0,
                        'dateUpdated' => $now,
                    ],
                    ['id' => $id],
                )
                ->execute();

            Craft::$app->getCache()->delete(self::CACHE_KEY_CIRCUIT . $id);
        } catch (Throwable $e) {
            Craft::error(
                'Failed to reset SIEM forwarder circuit ' . $id . ': ' . $e->getMessage(),
                'password-policy',
            );

            return false;
        }

        return true;
    }

    /**
     * Persists a forwarder model to its record. Handles both new
     * (insert) and existing (update) paths. Returns false when the
     * model fails validation; the caller pulls per-field errors off the
     * model.
     *
     * Encryption of `authToken` and the per-protocol nulling of the
     * unused half of the row both happen at the model boundary in
     * `SiemForwarderModel::toRecordAttributes()`.
     *
     * @param SiemForwarderModel $forwarder
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function saveForwarder(SiemForwarderModel $forwarder): bool
    {
        if (!$forwarder->validate()) {
            return false;
        }

        $record = $forwarder->id !== null
            ? SiemForwarderRecord::findOne(['id' => $forwarder->id])
            : null;

        if ($record === null) {
            $record = new SiemForwarderRecord();
            $forwarder->uid = $forwarder->uid ?: StringHelper::UUID();
        }

        foreach ($forwarder->toRecordAttributes() as $key => $value) {
            $record->{$key} = $value;
        }

        $record->uid = $forwarder->uid ?? StringHelper::UUID();

        // Save without re-validating — model already passed
        // validate() above; ActiveRecord's own rules don't apply.
        $record->save(false);

        $forwarder->id = (int)$record->id;

        return true;
    }

    /**
     * Fires a synthetic `siem_test` audit event and forwards the
     * resulting row through `$forwarder` synchronously. Surfaces
     * success / failure to the caller via boolean return + thrown
     * exception on infrastructure errors (e.g. table unwritable). The
     * "Send test event" CP button POSTs through the controller into
     * this method.
     *
     * The synthetic event must already be registered in
     * `AuditLogService::ALLOWED_DETAILS_BY_EVENT` (see G5 — fail-closed
     * registry). Without that entry the audit row drops on the floor,
     * and the test would erroneously surface "no row to forward."
     *
     * Throws `RuntimeException` when the audit row can't be located
     * after the write (DB transient or registry gap) — the caller
     * surfaces the message verbatim. Throws nothing on a forward
     * failure; the boolean return distinguishes "endpoint accepted"
     * from "endpoint refused or timed out."
     *
     * @param SiemForwarderModel $forwarder
     * @return bool true when the destination accepted the row, false on
     *     refusal / timeout
     *
     * @throws RuntimeException when the audit row can't be located
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendTestEvent(SiemForwarderModel $forwarder): bool
    {
        $currentUser = Craft::$app->getUser()->getIdentity();
        $userId = $currentUser?->id;

        $rowId = PasswordPolicy::$plugin->getAuditLog()->logEvent(
            userId: $userId,
            event: 'siem_test',
            details: ['source' => 'admin'],
            outcome: 'success',
        );

        // Fetch the just-written row by primary key. Using the returned
        // id instead of `ORDER BY id DESC LIMIT 1` removes the race
        // against concurrent admin clicks — without it, a second test
        // arriving between this write and read would steal the lookup.
        if ($rowId === null) {
            throw new RuntimeException(
                'Test event could not be written to the audit log; the log may be disabled or misconfigured.',
            );
        }

        $row = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['id' => $rowId])
            ->one();

        if (!is_array($row)) {
            throw new RuntimeException(
                'Test event was logged but could not be located for forwarding.',
            );
        }

        return $this->forward($row, $forwarder);
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds the request headers for the HTTP transport.
     *
     * `Content-Type` is fixed: the body is canonical JSON. Custom headers
     * come next, each value resolved through {@see _resolveEnvValue()} so
     * a credential can live in the environment rather than the database.
     * The `Authorization` header derived from `authType` goes last; a
     * `basic` credential is the operator's `user:password` string, which is
     * base64-encoded here (HTTP Basic's own encoding, not a secrecy
     * measure).
     *
     * The model's header validator already refuses a custom entry that
     * would collide with either of those, so the ordering here can't
     * silently overwrite operator intent.
     *
     * An unresolvable value throws rather than being dropped. A dropped
     * credential header reaches the collector as an unauthenticated
     * request, and the operator then debugs a 401 from the far end instead
     * of reading "this env var is not set" in their own log.
     *
     * @param SiemForwarderModel $forwarder
     * @return array<string, string>
     *
     * @throws RuntimeException when a header value or the auth token is
     *     empty, or names an env variable that isn't set
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildHttpHeaders(SiemForwarderModel $forwarder): array
    {
        $headers = ['Content-Type' => 'application/json'];

        foreach ($forwarder->headers ?? [] as $name => $value) {
            $resolved = $this->_resolveEnvValue($value);

            if ($resolved === null) {
                throw new RuntimeException(sprintf(
                    'The %s header is empty once resolved.',
                    $name,
                ));
            }

            $headers[(string)$name] = $resolved;
        }

        if ($forwarder->authType === SiemForwarderModel::AUTH_TYPE_NONE) {
            return $headers;
        }

        $token = $this->_resolveEnvValue($forwarder->authToken);

        if ($token === null) {
            throw new RuntimeException('The forwarder auth token is empty once resolved.');
        }

        $headers['Authorization'] = match ($forwarder->authType) {
            SiemForwarderModel::AUTH_TYPE_BASIC => 'Basic ' . base64_encode($token),
            SiemForwarderModel::AUTH_TYPE_BEARER => 'Bearer ' . $token,
            default => throw new RuntimeException(sprintf(
                'Unsupported forwarder authentication type "%s".',
                $forwarder->authType,
            )),
        };

        return $headers;
    }

    /**
     * Builds the operator-facing failure message for a non-2xx response:
     * an `HTTP <status>` status line plus a bounded slice of the response
     * body (capped at {@see ERROR_BODY_READ_LIMIT} bytes,
     * whitespace-trimmed). Many collectors return an empty body on error,
     * in which case only the status line is kept. NEVER echoes back the
     * request body or any credential.
     *
     * @param int $statusCode the non-2xx HTTP status returned
     * @param string $responseBody the raw response body
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildResponseError(int $statusCode, string $responseBody): string
    {
        $message = 'HTTP ' . $statusCode;
        $snippet = trim($responseBody);

        if ($snippet === '') {
            return $message;
        }

        if (strlen($snippet) > self::ERROR_BODY_READ_LIMIT) {
            $snippet = substr($snippet, 0, self::ERROR_BODY_READ_LIMIT) . '...';
        }

        return $message . ': ' . $snippet;
    }

    /**
     * Builds an RFC 5424 syslog frame for `$auditRow`.
     *
     * Frame shape:
     *
     *     <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
     *
     * - PRI = facility * 8 + severity (133 for local0.notice).
     * - VERSION = 1 (RFC 5424).
     * - TIMESTAMP = ISO 8601 with explicit `Z` suffix.
     * - HOSTNAME = the system uname.
     * - APP-NAME = `password-policy`.
     * - PROCID = current process id.
     * - MSGID = `audit-log`.
     * - STRUCTURED-DATA = `-` (no SDATA blocks).
     * - MSG = canonical JSON of the audit row via
     *   `AuditLogService::canonicalize()` — recursively key-sorted,
     *   BOM-free, `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`. This
     *   is the SAME byte sequence the HTTP transport POSTs and the webhook
     *   forwarder signs and sends, so every consumer sees an identical
     *   body (the byte-parity contract documented on `WebhookService`).
     *
     * @param array<string, mixed> $auditRow
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildSyslogFrame(array $auditRow): string
    {
        $priority = (self::SYSLOG_FACILITY_LOCAL0 * 8) + self::SYSLOG_SEVERITY_NOTICE;
        $timestamp = Carbon::now('UTC')->format('Y-m-d\TH:i:s\Z');
        $hostname = (string)(gethostname() ?: '-');
        $procId = (string)getmypid() ?: '-';
        $body = AuditLogService::canonicalize($auditRow);

        return sprintf(
            '<%d>1 %s %s %s %s %s - %s',
            $priority,
            $timestamp,
            $hostname,
            'password-policy',
            $procId,
            'audit-log',
            $body,
        );
    }

    /**
     * Returns the configured circuit-breaker cooldown window in seconds.
     * Falls back to 300s if the setting is somehow non-positive.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _circuitCooldownSeconds(): int
    {
        $configured = PasswordPolicy::$plugin->getSettings()->siemCircuitCooldownSeconds;

        return $configured > 0 ? $configured : 300;
    }

    /**
     * Returns the configured failure threshold that opens the circuit.
     * Falls back to 5 if the setting is somehow non-positive.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _circuitFailureThreshold(): int
    {
        $configured = PasswordPolicy::$plugin->getSettings()->siemCircuitFailureThreshold;

        return $configured > 0 ? $configured : 5;
    }

    /**
     * Wraps an RFC 5424 message in the transport framing `$forwarder` is
     * configured for, and returns the exact bytes to write to the stream.
     *
     * Two framings, and switching one is a wire-format change in both
     * directions, which is why it's a per-forwarder column rather than a
     * flip:
     *
     *  - `octet-counted` produces `MSG-LEN SP SYSLOG-MSG` per RFC 5425
     *    §4.3, where MSG-LEN is the message's octet count. §4.3.1 makes
     *    reading that length a MUST for a transport receiver, so this is
     *    the conformant shape for port 6514 and the default. No trailing
     *    newline: the length delimits the message.
     *  - `newline` appends `"\n"`, RFC 6587-style non-transparent framing,
     *    which is what rsyslog's `imtcp` accepts by default.
     *
     * @param SiemForwarderModel $forwarder
     * @param string $frame the RFC 5424 syslog message
     * @return string
     *
     * @throws RuntimeException on a framing value neither branch handles
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _framePayload(SiemForwarderModel $forwarder, string $frame): string
    {
        return match ($forwarder->framing) {
            SiemForwarderModel::FRAMING_NEWLINE => $frame . "\n",
            SiemForwarderModel::FRAMING_OCTET_COUNTED => strlen($frame) . ' ' . $frame,
            default => throw new RuntimeException(sprintf(
                'Unsupported forwarder message framing "%s".',
                $forwarder->framing,
            )),
        };
    }

    /**
     * POSTs the canonical JSON of `$auditRow` to `$forwarder`'s HTTPS
     * collector. Throws on any non-success outcome — `forward()` wraps the
     * call in the failure-mode try/catch that records the failure and
     * bumps the circuit breaker.
     *
     * The Guzzle configuration mirrors `WebhookService::dispatch()` and is
     * load-bearing in four places:
     *
     *  - `verify => true` (or the operator's own CA bundle) so peer
     *    verification is never off. Unlike the syslog transport there is
     *    no per-forwarder opt-out: this request carries a credential, and
     *    an unverified peer is where a credential gets stolen. This also
     *    overrides a site-level `config/guzzle.php` that sets
     *    `verify => false`.
     *  - `http_errors => false` so a non-2xx doesn't throw a Guzzle
     *    exception with the request attached; the status is read and turned
     *    into a bounded diagnostic below instead.
     *  - `allow_redirects => false`. A 307/308 from the registered host
     *    would otherwise re-POST the audit row AND the credential to
     *    whatever `Location` the response names, on a host the operator
     *    never approved. A 3xx is a failure here.
     *  - A bounded error-body read, so a hostile or chatty collector can't
     *    balloon the plugin log.
     *
     * The resolved-URL https re-check is the fifth. The model rule only
     * sees a literal URL; an env-var reference resolves here, and this is
     * the only place a `$PP_SIEM_URL` that resolves to plaintext http can
     * be caught.
     *
     * @param SiemForwarderModel $forwarder
     * @param array<string, mixed> $auditRow
     * @return void
     *
     * @throws RuntimeException on an empty or non-https resolved URL, a
     *     transport failure, or a non-2xx response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _postToHttp(SiemForwarderModel $forwarder, array $auditRow): void
    {
        $url = App::parseEnv((string)$forwarder->url);

        if (!is_string($url) || $url === '') {
            throw new RuntimeException('The forwarder endpoint URL is empty once resolved.');
        }

        if (stripos($url, 'https://') !== 0) {
            throw new RuntimeException(
                'The resolved endpoint URL is not https://; refusing to send audit rows over plaintext.',
            );
        }

        $verify = true;

        if ($forwarder->tlsCaBundlePath !== null && $forwarder->tlsCaBundlePath !== '') {
            $resolvedBundle = App::parseEnv($forwarder->tlsCaBundlePath);

            if (is_string($resolvedBundle) && $resolvedBundle !== '') {
                $verify = $resolvedBundle;
            }
        }

        $client = Craft::createGuzzleClient([
            'verify' => $verify,
            'http_errors' => false,
            'allow_redirects' => false,
            'timeout' => self::HTTP_TIMEOUT_SECONDS,
        ]);

        $response = $client->request('POST', $url, [
            'headers' => $this->_buildHttpHeaders($forwarder),
            'body' => AuditLogService::canonicalize($auditRow),
        ]);

        $statusCode = $response->getStatusCode();

        // Only a 2xx is a success. 3xx (redirect, not followed), 4xx, and
        // 5xx all count as failures.
        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException(
                $this->_buildResponseError($statusCode, $response->getBody()->getContents()),
            );
        }
    }

    /**
     * Records a forward failure. Increments cache + DB counter and
     * opens the circuit when the threshold is crossed. Best-effort:
     * a write failure is logged but never rethrown (the originating
     * forward already failed; we don't want to compound the noise).
     *
     * @param SiemForwarderModel $forwarder
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordFailure(SiemForwarderModel $forwarder): void
    {
        if ($forwarder->id === null) {
            return;
        }

        $threshold = $this->_circuitFailureThreshold();
        $cache = Craft::$app->getCache();
        $cacheKey = self::CACHE_KEY_CIRCUIT . $forwarder->id;

        $current = (int)($cache->get($cacheKey) ?: 0);
        $next = $current + 1;
        $cache->set($cacheKey, (string)$next, $this->_circuitCooldownSeconds());

        $update = [
            'consecutiveFailures' => $next,
            'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
        ];

        if ($next >= $threshold && $forwarder->circuitOpenAt === null) {
            $update['circuitOpenAt'] = Carbon::now('UTC')->format('Y-m-d H:i:s');
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    SiemForwarderRecord::tableName(),
                    $update,
                    ['id' => $forwarder->id],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to update SIEM forwarder failure state: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Records a forward success. Resets the cache counter and clears
     * the DB circuit state — but only writes to the DB when the prior
     * state was non-zero, so a steady-state of healthy forwards
     * doesn't generate a row update on every send.
     *
     * @param SiemForwarderModel $forwarder
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordSuccess(SiemForwarderModel $forwarder): void
    {
        if ($forwarder->id === null) {
            return;
        }

        $cache = Craft::$app->getCache();
        $cache->delete(self::CACHE_KEY_CIRCUIT . $forwarder->id);

        // Skip the DB write when the prior state was already clean.
        if ($forwarder->consecutiveFailures === 0 && $forwarder->circuitOpenAt === null) {
            return;
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    SiemForwarderRecord::tableName(),
                    [
                        'consecutiveFailures' => 0,
                        'circuitOpenAt' => null,
                        'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    ],
                    ['id' => $forwarder->id],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to clear SIEM forwarder circuit on success: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Resolves an operator-supplied value that may be an env-var
     * reference, and returns null when the result isn't usable.
     *
     * "Not usable" covers three cases: null or empty input, a resolved
     * value that is empty, and an env reference that came back unchanged
     * (Craft's `App::parseEnv()` returns the literal `$VAR` string when
     * the variable isn't set, so an unchanged `$`-prefixed value means the
     * environment has no such variable). The last case is the one worth
     * catching: sending the literal `$PP_SIEM_TOKEN` as a credential looks
     * like an authentication failure from the collector's side and tells
     * the operator nothing.
     *
     * @param string|null $value
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveEnvValue(?string $value): ?string
    {
        if ($value === null || trim($value) === '') {
            return null;
        }

        $resolved = App::parseEnv($value);

        if (!is_string($resolved) || trim($resolved) === '') {
            return null;
        }

        if (str_starts_with($value, '$') && $resolved === $value) {
            return null;
        }

        return $resolved;
    }

    /**
     * Opens a TLS stream to `$forwarder` and writes the syslog message,
     * framed per {@see _framePayload()}. Throws on any failure — caller
     * wraps in the failure-mode try/catch inside `forward()`.
     *
     * Stream context honors:
     *  - `verify_peer` per the forwarder's `tlsCertVerify`
     *  - `cafile` per the env-resolved `tlsCaBundlePath` (only when set)
     *  - `verify_peer_name` follows `verify_peer` — operators who turn
     *    off cert verification expect host verification to follow
     *
     * Per `security.md`, this overrides any site-level
     * `config/guzzle.php` `verify => false` because we use a raw stream
     * socket, not Guzzle. Defense-in-depth.
     *
     * @param SiemForwarderModel $forwarder
     * @param string $frame the RFC 5424 syslog frame
     * @return void
     *
     * @throws RuntimeException on a missing host or port, connect failure,
     *     TLS handshake error, or partial write
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _writeToSocket(SiemForwarderModel $forwarder, string $frame): void
    {
        // Both are `required` on this protocol, so a row reaching here
        // without them was written around the model. Refuse rather than
        // open a socket to `tls://:0`.
        if ($forwarder->host === null || $forwarder->host === '' || $forwarder->port === null) {
            throw new RuntimeException('The forwarder has no host and port to connect to.');
        }

        $contextOptions = [
            'ssl' => [
                'verify_peer' => $forwarder->tlsCertVerify,
                'verify_peer_name' => $forwarder->tlsCertVerify,
            ],
        ];

        if ($forwarder->tlsCaBundlePath !== null && $forwarder->tlsCaBundlePath !== '') {
            $resolved = App::parseEnv($forwarder->tlsCaBundlePath);

            if (is_string($resolved) && $resolved !== '') {
                $contextOptions['ssl']['cafile'] = $resolved;
            }
        }

        $context = stream_context_create($contextOptions);
        $address = sprintf('tls://%s:%d', $forwarder->host, $forwarder->port);
        $errno = 0;
        $errstr = '';

        $socket = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            self::TLS_CONNECT_TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($socket === false) {
            throw new RuntimeException(sprintf(
                'TLS connect failed (%d): %s',
                $errno,
                $errstr !== '' ? $errstr : 'unknown error',
            ));
        }

        // Bound the write/read window. `stream_socket_client`'s timeout
        // argument covers connect only — a half-open peer (TLS handshake
        // completes, the socket accepts, but the far end never drains the
        // buffer) would otherwise stall the write until the whole job TTR
        // elapses, and the circuit breaker would never engage because no
        // exception is raised. `stream_set_timeout` + the explicit
        // `timed_out` check below turn that stall into a thrown
        // RuntimeException, which `forward()` records as a failure.
        stream_set_timeout($socket, self::TLS_CONNECT_TIMEOUT);

        // Frame per the forwarder's `framing` column: an RFC 5425 octet
        // count, or the legacy trailing newline.
        $payload = $this->_framePayload($forwarder, $frame);
        $written = @fwrite($socket, $payload);

        // `stream_get_meta_data()` must be read BEFORE the socket is
        // closed — `timed_out` reflects whether the last fwrite/fread
        // hit the stream timeout (rather than completing).
        $meta = stream_get_meta_data($socket);
        @fclose($socket);

        if (!empty($meta['timed_out'])) {
            throw new RuntimeException('TLS write timed out; the SIEM peer accepted the connection but did not drain the frame.');
        }

        if ($written === false || $written < strlen($payload)) {
            throw new RuntimeException('TLS write was incomplete or failed.');
        }
    }
}
