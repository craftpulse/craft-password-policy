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
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\events\AuditChainRotatedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
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
        'account_locked' => ['source'],
        'account_unlocked' => ['source'],
        'breach_detected' => ['source'],
        'hibp_breach_detected' => ['source', 'failMode'],
        'hibp_check_failed' => ['source', 'failMode'],
        'password_changed' => ['method', 'reason', 'source'],
        'password_reset_forced' => ['reason', 'source'],
        'policy_changed' => ['diff', 'policyId', 'policyName'],
        'siem_test' => ['source'],
        'webhook_test' => ['source'],
    ];

    /**
     * Stable sentinel for the genesis row's `previousHash`. Sixty-four
     * zero hex chars — same width as a SHA-256 digest, so verifier
     * chain-walks treat it as a hash without a null-handling branch.
     *
     * Single source of truth — referenced by `AuditController` (the
     * G2 verifier CLI) and the `m260507_081852_RecomputeAuditLogChain`
     * migration. Drift between the writer and either reader silently
     * invalidates every chain hash in the table, so the constant lives
     * in one place and the readers import it.
     *
     * @var string
     */
    public const GENESIS_PREVIOUS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Canonical-payload `dateCreated` format. UTC, ISO 8601 with the
     * literal `Z` suffix (not `+00:00`). Sub-second precision dropped —
     * MySQL's `DATETIME` column is one-second resolution anyway. The
     * verifier produces bit-identical output only when the format
     * matches exactly.
     *
     * Single source of truth — referenced by `AuditController` (the
     * G2 verifier CLI) and the `m260507_081852_RecomputeAuditLogChain`
     * migration. Drift between the writer and either reader silently
     * invalidates every chain hash in the table, so the constant lives
     * in one place and the readers import it.
     *
     * @var string
     */
    public const CANONICAL_DATE_FORMAT = 'Y-m-d\TH:i:s\Z';

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
        $sorted = self::_sortRecursive($payload);

        return Json::encode(
            $sorted,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );
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
                    "Audit event '{event}' fired without a registry entry — row dropped (fail-closed). Add the event class to AuditLogService::ALLOWED_DETAILS_BY_EVENT before firing.",
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

            // HMAC IP address (never store raw). Keyed via the same
            // resolver as `_hashUserIdentifier()` — bare SHA-256 over
            // IPv4's 32-bit space is rainbow-tableable, and rotating
            // the `auditPiiKey` should destroy correlation against
            // both columns symmetrically.
            $ipHash = null;
            $request = Craft::$app->getRequest();
            if (!$request->getIsConsoleRequest()) {
                $ip = $request->getUserIP();
                if ($ip !== null) {
                    $ipHash = hash_hmac('sha256', $ip, $this->_resolveAuditPiiKey());
                }
            }

            // HMAC user identifier for post-deletion correlation
            $userIdentifier = null;
            if ($userId !== null) {
                $userIdentifier = $this->_hashUserIdentifier($userId);
            }

            $resolvedChangedByUserId = $changedByUserId ?? $this->_getCurrentAdminId();
            $dateCreated = Carbon::now('UTC');
            $uid = StringHelper::UUID();

            // Chain write: SELECT ... FOR UPDATE locks the latest rowHash
            // until the new row's INSERT commits. Two concurrent inserts
            // serialise — the second one reads the first's committed
            // rowHash as its own previousHash. Yii's `Query` builder
            // doesn't expose a `FOR UPDATE` clause, so we issue the
            // locking read as a raw command. The table name is a
            // compile-time constant — no user-input interpolation, no
            // injection surface.
            //
            // The transaction MUST wrap saveElement(). Step 5
            // converted the writer from a raw record insert to an
            // element pipeline — Craft inserts the craft_elements row
            // first, then the element's afterSave() inserts the
            // audit_log row. Both inserts share the lock; without the
            // wrapping transaction two concurrent logEvent() calls
            // could read the same previousHash and produce parallel
            // chain forks.
            $db = Craft::$app->getDb();
            $tableName = $db->getSchema()->getRawTableName('{{%passwordpolicy_audit_log}}');

            $insertedId = null;

            $db->transaction(function() use (
                $db,
                $tableName,
                $userId,
                $resolvedChangedByUserId,
                $event,
                $outcome,
                $source,
                $filteredDetails,
                $ipHash,
                $userIdentifier,
                $dateCreated,
                $uid,
                &$insertedId,
            ): void {
                $previousHash = $db
                    ->createCommand("SELECT [[rowHash]] FROM {$db->quoteTableName($tableName)} ORDER BY [[id]] DESC LIMIT 1 FOR UPDATE")
                    ->queryScalar();

                if (!is_string($previousHash) || $previousHash === '') {
                    $previousHash = self::GENESIS_PREVIOUS_HASH;
                }

                // Canonical-payload order matches the pre-element writer
                // byte-for-byte. The element-pipeline refactor (Step 5)
                // is additive — the element layer wraps the same audit
                // row shape that previously lived under a flat record
                // writer, so canonicalize() input is unchanged. Every
                // existing chain hash continues to verify.
                $canonicalPayload = self::canonicalize([
                    'changedByUserId' => $resolvedChangedByUserId,
                    'dateCreated' => $dateCreated->format(self::CANONICAL_DATE_FORMAT),
                    'details' => $filteredDetails,
                    'event' => $event,
                    'ipHash' => $ipHash,
                    'outcome' => $outcome,
                    'source' => $source,
                    'uid' => $uid,
                    'userId' => $userId,
                    'userIdentifier' => $userIdentifier,
                ]);

                $rowHash = hash('sha256', $canonicalPayload . $previousHash);

                // The element pipeline assigns `craft_elements.id` +
                // `craft_elements.uid` + `craft_elements.dateCreated`
                // from the element's properties (or auto-allocates when
                // unset). We explicitly set `uid` + `dateCreated` so
                // the canonical-payload bytes match the persisted
                // values. `id` is auto-allocated by Craft from the
                // craft_elements row, then the element's afterSave()
                // writes the paired audit_log row with that id.
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
                $element->userIdentifier = $userIdentifier;
                $element->previousHash = $previousHash;
                $element->rowHash = $rowHash;

                if (!Craft::$app->getElements()->saveElement($element, runValidation: false)) {
                    throw new \RuntimeException(
                        'AuditLogElement save failed: ' . implode('; ', $element->getFirstErrors()),
                    );
                }

                // Capture the new row's primary key for the return
                // value. Read from the saved element rather than the
                // raw lastInsertID — works through Yii's identity-map
                // cache.
                $insertedId = (int)$element->id;
            });

            return $insertedId;
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
        $threshold = Carbon::now('UTC')->subDays($daysToKeep)->format('Y-m-d H:i:s');

        // Capture the pre-prune chain head + the highest id about to be
        // deleted. Done BEFORE the delete so the rows still exist; both
        // are needed for the rotation event payload regardless of how
        // many rows the delete actually removes.
        $endRow = (new Query())
            ->select(['id', 'rowHash'])
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['<', 'dateCreated', $threshold])
            ->orderBy(['id' => SORT_DESC])
            ->limit(1)
            ->one();

        // Audit retention is a compliance requirement — rows must be
        // GONE from disk past the retention boundary (L3 of the Step 5
        // invariants). Element soft-delete via `dateDeleted` is NOT
        // acceptable for this path. Delete the paired
        // `craft_elements` rows; the FK CASCADE on
        // `audit_log.id → craft_elements.id` drops the audit rows in
        // the same statement.
        //
        // Bulk DELETE on craft_elements rather than per-row
        // `deleteElementById($id, hardDelete: true)` — the latter
        // would fire ElementHelper lifecycle events per row, which
        // both spams the event bus and bumps memory on a large prune
        // batch. Retention is a bulk operation by design.
        //
        // SELECT-then-DELETE rather than DELETE-with-subquery so the
        // deletion happens against a fixed id set (avoids MySQL's
        // "can't reopen table in subquery" edge cases on some
        // versions). Audit retention prune batches scale with
        // `daysToKeep` and the event volume between prunes — for
        // production volumes the id-list materialisation cost is in
        // the noise.
        $expiredIds = (new Query())
            ->select(['id'])
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['<', 'dateCreated', $threshold])
            ->column();

        $deleted = 0;
        if ($expiredIds !== []) {
            $deleted = Craft::$app->getDb()->createCommand()
                ->delete('{{%elements}}', ['id' => $expiredIds])
                ->execute();
        }

        if ($deleted < 1 || !is_array($endRow)) {
            return $deleted;
        }

        // Resolve the new chain head (the first surviving row). When the
        // prune emptied the table we have no anchor for downstream
        // listeners — skip the event entirely so consumers don't have
        // to handle a "rotation with no head" payload.
        $startRow = (new Query())
            ->select(['id', 'rowHash'])
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['id' => SORT_ASC])
            ->limit(1)
            ->one();

        if (!is_array($startRow)) {
            return $deleted;
        }

        $this->trigger(
            self::EVENT_AUDIT_CHAIN_ROTATED,
            new AuditChainRotatedEvent([
                'startId' => (int)$startRow['id'],
                'startRowHash' => (string)$startRow['rowHash'],
                'endId' => (int)$endRow['id'],
                'endRowHash' => (string)$endRow['rowHash'],
                'rotatedAt' => Carbon::now('UTC')->toDateTime(),
            ]),
        );

        return $deleted;
    }

    // Private Methods
    // =========================================================================

    /**
     * Recursively sorts an array's string keys for canonicalisation.
     * Numeric-keyed (list) arrays preserve their integer order — they
     * encode as JSON arrays where order is the contract.
     *
     * @param array<mixed, mixed> $value
     * @return array<mixed, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _sortRecursive(array $value): array
    {
        foreach ($value as $key => $inner) {
            if (is_array($inner)) {
                $value[$key] = self::_sortRecursive($inner);
            }
        }

        ksort($value, SORT_STRING);

        return $value;
    }

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

    /**
     * Creates an HMAC-SHA-256 hash of the user's email for post-deletion correlation.
     *
     * The HMAC secret is resolved via {@see _resolveAuditPiiKey()} —
     * a dedicated `auditPiiKey` (env-var-backed via
     * `CRAFT_AUDIT_PII_KEY` + `config/password-policy.php`) with a
     * `securityKey` fallback. Rotating the dedicated key destroys
     * correlation against new rows without touching session signing,
     * CSRF tokens, asset URLs, or anything else `securityKey` anchors.
     *
     * @param int $userId
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hashUserIdentifier(int $userId): ?string
    {
        $user = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null || $user->email === null) {
            return null;
        }

        return hash_hmac('sha256', $user->email, $this->_resolveAuditPiiKey());
    }

    /**
     * Resolves the HMAC key for `userIdentifier` hashing.
     *
     * Reads `SettingsModel::$auditPiiKey` first (operator-managed via
     * `CRAFT_AUDIT_PII_KEY` env var → `config/password-policy.php`).
     * Falls back to `securityKey` when unset so dev installs that
     * skipped the generator still produce hashable rows.
     *
     * The fallback is intentional but the USP-grade rotation property
     * (key rotation destroys historical correlation without breaking
     * the rest of the site) only applies once the env var is set —
     * operators wanting the privacy lever MUST run
     * `ddev craft password-policy/audit/generate-pii-key` once and
     * redeploy.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveAuditPiiKey(): string
    {
        $configured = PasswordPolicy::$plugin->getSettings()->auditPiiKey;

        if (!empty($configured)) {
            return $configured;
        }

        return Craft::$app->getConfig()->getGeneral()->securityKey;
    }
}
