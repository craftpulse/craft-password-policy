<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\auditkit\engine\Canonicalizer;
use craftpulse\auditkit\engine\ChainWriter;
use craftpulse\auditkit\engine\ContextCapturer;
use craftpulse\auditkit\engine\Pruner;
use craftpulse\auditkit\events\ChainRotatedEvent;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\events\AuditChainRotatedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use RuntimeException;
use Throwable;
use yii\base\Component;

/**
 * Class AuditLogService
 *
 * Records security-relevant events without storing password data.
 * Runtime-enforced detail allowlist prevents accidental PII leakage.
 *
 * Hash chain (Phase G — G1)
 * -------------------------
 * Every row in `passwordpolicy_audit_log` is part of a SHA-256 forward
 * chain. Each row's `rowHash` column is the hex SHA-256 of
 * `canonicalize(payload) . previousHash`, where `previousHash` is the
 * `rowHash` of the row immediately preceding it in `id` order. The
 * genesis row's `previousHash` is sixty-four zero characters (a stable
 * sentinel — the chain-walk verifier never has to special-case "is this
 * the first row?" with a NULL check).
 *
 * The chain is auditor-facing: a verifier walking the table from id 1
 * forward must produce the same rowHash bytes the writer produced, or
 * a tamper has occurred. That contract is the whole reason
 * `canonicalize()` is bit-deterministic — alphabetical key order
 * (recursive), no whitespace, `JSON_UNESCAPED_SLASHES |
 * JSON_UNESCAPED_UNICODE`, `null` values preserved (not stripped),
 * booleans encoded as `true`/`false` (not coerced to `1`/`0`),
 * `dateCreated` formatted as the literal UTC string `Y-m-d\TH:i:s\Z`.
 *
 * Concurrency: row insert + chain hash computation runs inside a
 * `transaction()` with `SELECT ... FOR UPDATE` on the latest row's
 * `rowHash`. Two concurrent inserts cannot pick the same `previousHash`
 * — the second one waits for the first's commit, then reads the new
 * tail.
 *
 * Capture is universal. The chain runs on every edition (Lite included).
 * Edition gates apply to the dashboard / verifier UI / SIEM forwarder
 * / export — never to the underlying writes. See memory rule
 * `project_audit_capture_principle.md`.
 *
 * Per-event PII allowlist (Phase G — G5)
 * --------------------------------------
 * Every event class fired through `logEvent()` MUST have a registry
 * entry in `ALLOWED_DETAILS_BY_EVENT`. The registry is the codified
 * privacy contract — for every event class an auditor can read exactly
 * which `details` keys the writer is permitted to persist, and nothing
 * outside that set will ever land on disk. Cross-referenced from
 * `docs/user/features/audit-logging.md` so the contract is the
 * customer-facing privacy-by-design statement.
 *
 * Enforcement is fail-closed: an event class without a registry entry
 * triggers a Yii warning AND drops the row entirely. Both halves are
 * intentional —
 *
 *  - silent-allow lets a typo'd event class string ("password_chnaged")
 *    leak any payload shape the caller controls forever, undetected;
 *  - silent-deny lets the same typo fall on the floor with no signal
 *    a developer can debug against.
 *
 * The fail-closed `return` lands BEFORE the `enableAuditLog` feature-
 * flag check on purpose. A missing registry entry is a programming
 * error (developer added a new event class without registering it),
 * and surfacing the warning regardless of whether audit logging is
 * currently enabled is the only way that error reaches a maintainer
 * before it reaches production. The dropped row is also fine in that
 * shape: with no registry entry there's no canonical allowlist, so
 * there's no coherent way to write the row anyway.
 *
 * The codebase-grep test in
 * `tests/Integration/Services/AuditAllowlistRegistryTest.php` enforces
 * the registry at test time — every `logEvent('<event>'` call site in
 * `src/` must resolve to a registry key, otherwise CI fails before
 * runtime ever sees the gap.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditLogService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Fired after `purgeOldEntries()` deletes one or more rows from the
     * audit log. The chain head moves forward; consumers use the event
     * payload to record the retention boundary in external systems
     * (SIEM, off-site archive, compliance dashboard) and to anchor the
     * verifier's next chain-walk at the new first surviving row.
     *
     * Skipped entirely when the prune deleted zero rows — listeners
     * never see no-op rotations.
     *
     * @event AuditChainRotatedEvent
     *
     * @since 5.2.0
     */
    public const EVENT_AUDIT_CHAIN_ROTATED = 'auditChainRotated';

    /**
     * Per-event allowlist of detail keys. Every event class fired
     * through `logEvent()` MUST have an entry here — see the class
     * docblock's "Per-event PII allowlist" section for the fail-closed
     * contract.
     *
     * The auditor reading this constant gets the complete privacy
     * surface in one place: for each event class, exactly which keys
     * the writer is permitted to persist. Anything not listed is
     * stripped at write time. An event class not listed at all drops
     * the row and warns.
     *
     * Edition: every event captures on every edition (`project_audit_
     * capture_principle.md`). This registry is edition-independent.
     *
     * Public so the inspection surfaces (CLI `password-policy/audit/
     * schema` and CP `AuditSchemaUtility`) can render it as auditor-
     * facing static evidence — the contract lives in code, not in
     * vendor documentation that can drift.
     *
     * @var array<string, string[]>
     */
    public const ALLOWED_DETAILS_BY_EVENT = [
        // Feature 5 inactive-account scan (Enterprise capture). `action`
        // is the closed enum string (report|notify|suspend); `source` is
        // the constant `inactive_scan`. Neither carries PII — the user is
        // correlated by the row's HMAC'd `userIdentifier`, never by an
        // identifier in the details payload.
        'account_inactive' => ['action', 'source'],
        'account_locked' => ['source'],
        'account_unlocked' => ['source'],
        // Auth Kit audit contract (Integration 1). The seven event
        // classes below are populated exclusively by
        // `integrations\AuthKitAuditSink`, which maps neutral
        // `craftpulse\authkit\audit\AuthEvent` names emitted by Warden
        // and Warp onto these PP classes. The sink passes a *mapped
        // variable* to `logEvent()`, so the codebase-grep test can't see
        // these targets — `AuditAllowlistRegistryTest` asserts the sink's
        // `AuthKitAuditSink::EVENT_MAP` values against these keys instead.
        //
        // Every key here is scalar, non-PII, and mirrors the neutral
        // contract's documented `details`: `method` is the login/registration
        // mechanism (`magic_link` | `otp` | `passkey` | `sso`), `provider`
        // the SSO identity-provider handle, `scope` the session-revocation
        // breadth (`single` | `others` | `backchannel`), `trigger` the
        // provisioning origin (`scim` | `jit`), and `source` the emitting
        // plugin handle (`warden` | `warp`).
        'auth_login' => ['method', 'provider', 'source'],
        'auth_registration' => ['method', 'source'],
        'breach_detected' => ['source'],
        'hibp_breach_detected' => ['source', 'failMode'],
        'hibp_check_failed' => ['source', 'failMode'],
        // Feature 1 new-device detection. `deviceLabel` is the
        // human-readable "Chrome on macOS" label — NEVER the raw
        // user-agent or raw IP, which the device row never stores either.
        'new_device' => ['source', 'deviceLabel'],
        // Auth Kit audit contract (Integration 1) — see `auth_login` above.
        'passkey_deleted' => ['source'],
        'passkey_enrolled' => ['source'],
        'password_changed' => ['method', 'reason', 'source'],
        'password_reset_forced' => ['reason', 'source'],
        'policy_changed' => ['diff', 'policyId', 'policyName'],
        // Auth Kit audit contract (Integration 1) — see `auth_login` above.
        'scim_deprovisioned' => ['trigger', 'source'],
        'scim_provisioned' => ['trigger', 'source'],
        'session_revoked' => ['scope', 'source'],
        'siem_test' => ['source'],
        'webhook_test' => ['source'],
    ];

    /**
     * Stable sentinel for the genesis row's `previousHash`. Sixty-four
     * zero hex chars — same width as a SHA-256 digest, so verifier
     * chain-walks treat it as a hash without a null-handling branch.
     *
     * Single source of truth — aliases {@see Canonicalizer::GENESIS_PREVIOUS_HASH}
     * (the shared Audit Kit engine now owns the value) while preserving the
     * `AuditLogService::GENESIS_PREVIOUS_HASH` reference that `AuditController`
     * (the G2 verifier CLI) and the `m260507_081852_RecomputeAuditLogChain`
     * migration import. Drift between the writer and either reader silently
     * invalidates every chain hash in the table, so the value lives in the kit
     * and every reader resolves to it.
     *
     * @var string
     */
    public const GENESIS_PREVIOUS_HASH = Canonicalizer::GENESIS_PREVIOUS_HASH;

    /**
     * Canonical-payload `dateCreated` format. UTC, ISO 8601 with the
     * literal `Z` suffix (not `+00:00`). Sub-second precision dropped —
     * MySQL's `DATETIME` column is one-second resolution anyway. The
     * verifier produces bit-identical output only when the format
     * matches exactly.
     *
     * Single source of truth — aliases {@see Canonicalizer::CANONICAL_DATE_FORMAT}
     * (the shared Audit Kit engine now owns the value) while preserving the
     * `AuditLogService::CANONICAL_DATE_FORMAT` reference that `AuditController`
     * (the G2 verifier CLI) and the `m260507_081852_RecomputeAuditLogChain`
     * migration import. Drift between the writer and either reader silently
     * invalidates every chain hash in the table, so the value lives in the kit
     * and every reader resolves to it.
     *
     * @var string
     */
    public const CANONICAL_DATE_FORMAT = Canonicalizer::CANONICAL_DATE_FORMAT;

    /**
     * Upper bound on the per-page row count the Feature 2 REST `audit`
     * endpoint will return, regardless of the caller's `limit` param. Caps
     * the cost of an unauthenticated-to-the-DB pagination loop and keeps a
     * single response bounded.
     *
     * @var int
     */
    public const MAX_API_QUERY_LIMIT = 200;

    // Static Methods
    // =========================================================================

    /**
     * Returns the canonical-JSON encoding of an audit-log payload.
     *
     * The output is the byte-stable form of `$payload` used as input to
     * the hash-chain SHA-256 computation. Rules:
     *
     *  - Keys are sorted alphabetically (`SORT_STRING`) recursively.
     *    Nested arrays are sorted at every depth.
     *  - JSON encoding flags: `JSON_UNESCAPED_SLASHES |
     *    JSON_UNESCAPED_UNICODE`. Forward slashes pass through as `/`,
     *    Unicode passes through as the original code points (not
     *    `\uXXXX` escapes).
     *  - `null` values are preserved as JSON `null` (not stripped).
     *  - Booleans encode as `true`/`false` (not coerced to `1`/`0`).
     *  - Integers encode bare (not quoted strings).
     *  - No whitespace anywhere in the output.
     *
     * The verifier (G2) calls this same method to recompute hashes when
     * walking the chain. Drift between the writer's output and the
     * verifier's output is a chain break — the auditor must be able to
     * trust that "I read these rows, hashed them with this code, and
     * got the same bytes" tells them the table hasn't been tampered
     * with.
     *
     * Lists (numerically-indexed arrays) are NOT sorted — `ksort()`
     * preserves the integer keys, and JSON-encoding a numeric-keyed
     * array emits a JSON array (not an object). Audit payloads
     * intentionally avoid mixed-key shapes; the canonical contract is
     * "associative arrays sort their string keys, lists keep their
     * order."
     *
     * @param array<mixed, mixed> $payload
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function canonicalize(array $payload): string
    {
        // Delegates to the shared Audit Kit engine, which is a byte-for-byte
        // lift of PP's original canonicalize()/_sortRecursive(). The kit is the
        // single canonicalisation code path across PP, Ledger, and Reeve — the
        // very property that lets an external verifier reproduce PP's live
        // 5.1.x rowHash bytes. This method is retained as PP's public API so
        // AuditController + the recompute migration + SiemService keep working.
        return Canonicalizer::canonicalize($payload);
    }

    // Public Methods
    // =========================================================================

    /**
     * Returns audit log entries for a specific user.
     *
     * @param int $userId
     * @param int $limit
     * @return array<int, array<string, mixed>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEventsForUser(int $userId, int $limit = 50): array
    {
        return (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['userId' => $userId])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($limit)
            ->all();
    }

    /**
     * Returns recent audit log entries with optional event filter.
     *
     * @param int $limit
     * @param string|null $eventFilter
     * @return array<int, array<string, mixed>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getRecentEvents(int $limit = 100, ?string $eventFilter = null): array
    {
        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($limit);

        if ($eventFilter !== null) {
            $query->andWhere(['event' => $eventFilter]);
        }

        return $query->all();
    }

    /**
     * Returns a redacted, paginated slice of the audit log for the Feature 2
     * REST `audit` endpoint. Read-only — no chain internals, no identifying
     * hashes leak.
     *
     * The exposed column set is deliberately narrow: `id`, `userId`,
     * `event`, `outcome`, `source`, the already-allowlisted privacy-safe
     * `details` payload, the country/region geo enrichment, `dateCreated`,
     * and `uid`. The `ipHash`, `userIdentifier`, `rowHash`, and
     * `previousHash` columns are NEVER serialised — `ipHash` /
     * `userIdentifier` can be identifying, and the chain hashes are
     * tamper-evidence internals that a read consumer has no use for.
     *
     * `$from` / `$to` filter on `dateCreated` (inclusive lower / upper).
     * `$limit` is clamped to {@see self::MAX_API_QUERY_LIMIT}; `$offset`
     * floors at 0. Rows come back newest-first.
     *
     * @param string|null $from inclusive lower bound (any strtotime-parseable
     *     string, treated as UTC), or null for no lower bound
     * @param string|null $to inclusive upper bound, or null for no upper bound
     * @param int $limit max rows (clamped)
     * @param int $offset skip count (floored at 0)
     * @return array{total: int, limit: int, offset: int, rows: array<int, array<string, mixed>>}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function queryEvents(?string $from = null, ?string $to = null, int $limit = 50, int $offset = 0): array
    {
        $limit = max(1, min($limit, self::MAX_API_QUERY_LIMIT));
        $offset = max(0, $offset);

        $columns = [
            'id',
            'userId',
            'event',
            'outcome',
            'source',
            'details',
            'geoCountry',
            'geoRegion',
            'dateCreated',
            'uid',
        ];

        $conditions = ['and'];

        if ($from !== null && $from !== '') {
            $conditions[] = ['>=', 'dateCreated', Carbon::parse($from, 'UTC')->format('Y-m-d H:i:s')];
        }

        if ($to !== null && $to !== '') {
            $conditions[] = ['<=', 'dateCreated', Carbon::parse($to, 'UTC')->format('Y-m-d H:i:s')];
        }

        $baseQuery = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where($conditions);

        $total = (int)(clone $baseQuery)->count();

        $rows = (clone $baseQuery)
            ->select($columns)
            ->orderBy(['dateCreated' => SORT_DESC, 'id' => SORT_DESC])
            ->limit($limit)
            ->offset($offset)
            ->all();

        // Normalise the JSON `details` column to a decoded array (or null)
        // so the endpoint emits structured JSON, not a JSON-string-in-JSON.
        foreach ($rows as &$row) {
            if (isset($row['details']) && is_string($row['details'])) {
                $decoded = Json::decodeIfJson($row['details']);
                $row['details'] = is_array($decoded) ? $decoded : null;
            }
        }
        unset($row);

        return [
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset,
            'rows' => $rows,
        ];
    }

    /**
     * Logs a security event to the audit log.
     *
     * Wrapped in try/catch to never block the parent operation. The
     * row's `rowHash` and `previousHash` are computed inside a
     * `SELECT ... FOR UPDATE` transaction — two concurrent inserts
     * cannot pick the same `previousHash`.
     *
     * Capture is universal — every edition writes audit rows. Edition
     * gates apply downstream (dashboard, verifier UI, forwarder,
     * export). The admin-managed `enableAuditLog` setting still gates
     * writes; that's a feature flag, not an edition gate.
     *
     * Returns the new row's primary key on success, or `null` when the
     * write was skipped or failed. Three null-return conditions:
     *
     *  1. The event class has no entry in `ALLOWED_DETAILS_BY_EVENT`
     *     (fail-closed registry — see class docblock).
     *  2. `enableAuditLog` is false (feature flag off).
     *  3. The write threw a `Throwable` (logged, swallowed — never
     *     blocks the parent operation).
     *
     * Most callers ignore the return value — the audit write is a
     * fire-and-forget side effect. The return contract exists for
     * `SiemService::sendTestEvent` + `WebhookService::sendTestEvent`,
     * which need to fetch the just-written row by primary key to
     * forward it. Looking up by `ORDER BY id DESC LIMIT 1` would race
     * against concurrent admin clicks; reading the returned id is
     * race-free.
     *
     * @param int|null $userId
     * @param string $event
     * @param array<string, mixed>|null $details
     * @param string $outcome
     * @param string|null $source
     * @param int|null $changedByUserId
     * @return int|null the new row's primary key, or null when skipped/failed
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function logEvent(
        ?int $userId,
        string $event,
        ?array $details = null,
        string $outcome = 'success',
        ?string $source = null,
        ?int $changedByUserId = null,
    ): ?int {
        // Fail-closed: an event class without a registry entry is a
        // programming error (typo in the call site, or new event class
        // shipped without registration). The warning fires BEFORE the
        // `enableAuditLog` feature-flag check intentionally — the
        // diagnostic must reach a maintainer regardless of whether the
        // feature is currently on. The dropped row is fine: without a
        // registry entry there's no canonical allowlist, so there's no
        // coherent shape to persist.
        if (!isset(self::ALLOWED_DETAILS_BY_EVENT[$event])) {
            Craft::warning(
                Craft::t(
                    'password-policy',
                    "Audit event '{event}' fired without a registry entry, so the row was dropped (fail-closed). Add the event class to AuditLogService::ALLOWED_DETAILS_BY_EVENT before firing.",
                    ['event' => $event],
                ),
                'password-policy',
            );

            return null;
        }

        $settings = PasswordPolicy::$plugin->getSettings();

        if (!$settings->enableAuditLog) {
            return null;
        }

        try {
            // Per-event allowlist — keys not declared for this event
            // class are stripped before insertion.
            $allowedKeys = self::ALLOWED_DETAILS_BY_EVENT[$event];
            $filteredDetails = null;
            if ($details !== null) {
                $filteredDetails = array_intersect_key(
                    $details,
                    array_flip($allowedKeys),
                );

                if (empty($filteredDetails)) {
                    $filteredDetails = null;
                }
            }

            // Determine source if not provided
            if ($source === null) {
                $source = $this->_detectSource();
            }

            // Privacy-safe context capture through the shared Audit Kit
            // ContextCapturer — HMAC of the IP and of the subject/actor
            // identities, keyed by PP's own `auditPiiKey` (env
            // `CRAFT_AUDIT_PII_KEY`, `securityKey` fallback). A bare SHA-256
            // over IPv4's 32-bit space is rainbow-tableable; keying it makes
            // key rotation destroy correlation across every hashed column
            // symmetrically. The env-var name + generate-pii-key command stay
            // PP's; only the HMAC mechanism moves to the kit.
            $capturer = new ContextCapturer(PasswordPolicy::$plugin->getSettings()->auditPiiKey);

            // HMAC IP address (never store raw). The raw IP is still fed to
            // PP's own Enterprise geo enrichment for country/region — but ONLY
            // the resolved country code + region are stored, never the raw IP.
            // Geo enrichment is gated on Enterprise + `geoIpEnabled`; the
            // edition check lives here at the call site, while the
            // `geoIpEnabled` flag is enforced inside `GeoIpService` (gate
            // exposure, not capture — the columns exist on every edition).
            $ipHash = null;
            $geoCountry = null;
            $geoRegion = null;
            $request = Craft::$app->getRequest();
            if (!$request->getIsConsoleRequest()) {
                $ip = $request->getUserIP();
                if ($ip !== null) {
                    $ipHash = $capturer->hashValue($ip);

                    if (PasswordPolicy::$plugin->getIsEnterprise()) {
                        $geo = PasswordPolicy::$plugin->getGeoIp()->lookup($ip);
                        if ($geo !== null) {
                            $geoCountry = $geo->countryCode;
                            $geoRegion = $geo->region;
                        }
                    }
                }
            }

            // HMAC user identifier for post-deletion correlation.
            $userIdentifier = $userId !== null
                ? $capturer->hashUserIdentifier($userId)
                : null;

            $resolvedChangedByUserId = $changedByUserId ?? $this->_getCurrentAdminId();

            // HMAC actor identifier — the immutable mirror of
            // `changedByUserId`. This, NOT the FK int, enters the canonical
            // hash payload: `changedByUserId` is `ON DELETE SET NULL`, so
            // hashing it would make deleting an admin (GDPR erasure) recompute
            // a different rowHash and report the chain as tampered. The HMAC
            // is set once here and never mutates.
            $changedByIdentifier = $resolvedChangedByUserId !== null
                ? $capturer->hashUserIdentifier($resolvedChangedByUserId)
                : null;
            $dateCreated = Carbon::now('UTC');
            $uid = StringHelper::UUID();

            // Canonical-payload key set (alphabetical): changedByIdentifier,
            // dateCreated, details, event, ipHash, outcome, source, uid,
            // userIdentifier.
            //
            // The mutable FK ints `userId` + `changedByUserId` are
            // DELIBERATELY EXCLUDED. Both are `ON DELETE SET NULL`, so deleting
            // a user nulls them on every historical row and the verifier would
            // then recompute a different rowHash — making GDPR erasure
            // indistinguishable from tampering. We hash the IMMUTABLE HMAC
            // identities instead: `userIdentifier` (the subject) and
            // `changedByIdentifier` (the actor), both set once at write and
            // never mutated. Same exclusion-by-mutability reasoning as the geo
            // columns (post-insert metadata that must not enter the hash).
            //
            // ⚠️ BIT-IDENTITY: this exact 9-key set + the kit Canonicalizer
            // bytes reproduce PP's live 5.1.x rowHash. Never add, remove, or
            // reorder a key here — every byte is regression-pinned by
            // AuditBitIdentityTest (golden vector) + the live-chain verify gate.
            $canonicalPayload = [
                'changedByIdentifier' => $changedByIdentifier,
                'dateCreated' => $dateCreated->format(self::CANONICAL_DATE_FORMAT),
                'details' => $filteredDetails,
                'event' => $event,
                'ipHash' => $ipHash,
                'outcome' => $outcome,
                'source' => $source,
                'uid' => $uid,
                'userIdentifier' => $userIdentifier,
            ];

            // Serialized chain write through the shared Audit Kit ChainWriter:
            // the `SELECT ... FOR UPDATE` tail read, the
            // `rowHash = sha256(canonicalize(payload) . previousHash)`
            // computation, and the wrapping transaction all live in the kit.
            // PP owns the payload shape (above) and the storage — the persist
            // closure saves the AuditLogElement exactly as before, so the
            // element pipeline's `craft_elements` + `audit_log` inserts run
            // inside the same locked transaction. Two concurrent logEvent()
            // calls serialise on the tail lock and cannot fork the chain.
            $result = (new ChainWriter())->write(
                Craft::$app->getDb(),
                '{{%passwordpolicy_audit_log}}',
                $canonicalPayload,
                function(string $previousHash, string $rowHash) use (
                    $userId,
                    $resolvedChangedByUserId,
                    $event,
                    $outcome,
                    $source,
                    $filteredDetails,
                    $ipHash,
                    $geoCountry,
                    $geoRegion,
                    $userIdentifier,
                    $changedByIdentifier,
                    $dateCreated,
                    $uid,
                ): int {
                    // The element pipeline assigns `craft_elements.id` + `uid` +
                    // `dateCreated` from the element's properties. We set `uid`
                    // + `dateCreated` explicitly so the persisted values match
                    // the canonical-payload bytes; `id` is auto-allocated, then
                    // afterSave() writes the paired audit_log row with that id.
                    $element = new AuditLogElement();
                    $element->uid = $uid;
                    $element->dateCreated = $dateCreated->toDateTime();
                    $element->userId = $userId;
                    $element->changedByUserId = $resolvedChangedByUserId;
                    $element->event = $event;
                    $element->outcome = $outcome;
                    $element->source = $source;
                    $element->details = $filteredDetails;
                    $element->ipHash = $ipHash;
                    // Geo enrichment — persisted on the element but DELIBERATELY
                    // absent from the canonical payload above. Geo is
                    // post-insert metadata; hashing it would break every
                    // existing chain row.
                    $element->geoCountry = $geoCountry;
                    $element->geoRegion = $geoRegion;
                    // `userId` + `changedByUserId` stay persisted (joins /
                    // display / SET NULL retention) but are no longer hashed —
                    // the HMAC identifiers ARE the hashed identity.
                    $element->userIdentifier = $userIdentifier;
                    $element->changedByIdentifier = $changedByIdentifier;
                    $element->previousHash = $previousHash;
                    $element->rowHash = $rowHash;

                    if (!Craft::$app->getElements()->saveElement($element, runValidation: false)) {
                        throw new RuntimeException(
                            'AuditLogElement save failed: ' . implode('; ', $element->getFirstErrors()),
                        );
                    }

                    return (int)$element->id;
                },
            );

            return is_int($result) ? $result : null;
        } catch (Throwable $e) {
            // Never block the parent operation
            Craft::error(
                'Failed to write audit log: ' . $e->getMessage(),
                'password-policy',
            );

            return null;
        }
    }

    /**
     * Purges audit log entries older than the specified number of days.
     *
     * On a successful prune (deleted >= 1 row AND >= 1 row remains) the
     * service triggers `EVENT_AUDIT_CHAIN_ROTATED` with the boundary
     * payload. A prune that deleted zero rows fires nothing — listeners
     * never see no-op rotations. A prune that emptied the table also
     * fires nothing because there's no surviving chain head to anchor.
     *
     * @param int $daysToKeep
     * @return int The number of entries purged
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function purgeOldEntries(int $daysToKeep = 365): int
    {
        // The id-prefix-safe prune mechanism (resolve the highest id past the
        // retention threshold, delete the whole `id <= maxId` prefix so the
        // survivors are always a clean chain suffix, then fire a rotation event
        // with the boundary anchors) lives in the shared Audit Kit Pruner. PP
        // supplies the retention window, the element-CASCADE delete closure,
        // and re-publishes the rotation under its own event contract.
        $pruner = new Pruner();

        // Bridge the kit's neutral ChainRotatedEvent onto PP's own
        // EVENT_AUDIT_CHAIN_ROTATED so existing listeners and the
        // AuditChainRotatedEvent payload contract are unchanged. The kit owns
        // the boundary computation; PP owns the event surface.
        $pruner->on(
            Pruner::EVENT_CHAIN_ROTATED,
            function(ChainRotatedEvent $event): void {
                $this->trigger(
                    self::EVENT_AUDIT_CHAIN_ROTATED,
                    new AuditChainRotatedEvent([
                        'startId' => $event->startId,
                        'startRowHash' => $event->startRowHash,
                        'endId' => $event->endId,
                        'endRowHash' => $event->endRowHash,
                        'rotatedAt' => $event->rotatedAt,
                    ]),
                );
            },
        );

        // Audit retention is a compliance delete — rows must be GONE from disk
        // past the boundary (element soft-delete via `dateDeleted` is not
        // acceptable here). Delete the paired `craft_elements` rows; the FK
        // CASCADE on `audit_log.id → craft_elements.id` drops the audit rows in
        // the same statement. Bulk DELETE (not per-row deleteElementById) so a
        // large prune doesn't spam element lifecycle events or balloon memory.
        // The Pruner resolves the id list against the audit table, so the
        // CASCADE targets exactly the pruned rows (the elements table holds
        // other element types too).
        return $pruner->prune(
            Craft::$app->getDb(),
            '{{%passwordpolicy_audit_log}}',
            $daysToKeep,
            static fn(array $expiredIds): int => Craft::$app->getDb()->createCommand()
                ->delete('{{%elements}}', ['id' => $expiredIds])
                ->execute(),
        );
    }

    // Private Methods
    // =========================================================================

    /**
     * Detects the source context for the current operation.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _detectSource(): string
    {
        if (Craft::$app->getRequest()->getIsConsoleRequest()) {
            return 'cli';
        }

        /** @var \craft\elements\User|null $currentUser */
        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser !== null && $currentUser->admin) {
            return 'admin';
        }

        return 'self-service';
    }

    /**
     * Returns the current admin's user ID if in an admin context.
     *
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getCurrentAdminId(): ?int
    {
        if (Craft::$app->getRequest()->getIsConsoleRequest()) {
            return null;
        }

        /** @var \craft\elements\User|null $currentUser */
        $currentUser = Craft::$app->getUser()->getIdentity();

        return $currentUser?->id;
    }
}
