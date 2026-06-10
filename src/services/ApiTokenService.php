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
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\ApiTokenModel;
use craftpulse\passwordpolicy\records\ApiTokenRecord;
use DateTime;
use yii\base\Component;

/**
 * Class ApiTokenService
 *
 * Owns the `passwordpolicy_api_tokens` write + read path for Feature 2 (the
 * read-only REST surface, Enterprise). Issues, resolves, revokes, and prunes
 * Bearer tokens.
 *
 * **Security model.**
 *
 *  - Tokens are minted via `Craft::$app->getSecurity()->generateRandomString()`
 *    (CSPRNG-backed) and shown to the operator EXACTLY ONCE at issue time.
 *  - Only the SHA-256 `tokenHash` and a short `tokenPrefix` (first 8 chars)
 *    are persisted. The plaintext is never stored and is unrecoverable after
 *    `issue()` returns.
 *  - `findByToken()` hashes the candidate and looks up by digest. The hash
 *    column is unique, so the lookup is a single indexed equality — but the
 *    final accept/reject decision uses `hash_equals()` for a constant-time
 *    compare on the resolved row, so a near-miss can't leak timing about
 *    which prefix bytes matched.
 *  - Expired tokens (non-null `expiresAt` in the past) resolve to `null` —
 *    `findByToken()` treats expiry identically to "no such token" so the
 *    caller returns a uniform 401 either way (no existence oracle).
 *
 * Date handling: `Carbon` (service layer) for the timestamps written to /
 * compared against the table — never `DateTimeHelper` here, per the
 * "DateTimeHelper in elements/queries, Carbon in services" split.
 *
 * Edition: the REST surface is Enterprise-only, but this service carries NO
 * edition gate — the gate lives on the CP token-manager controller (the only
 * writer) and the `ApiController` (the only reader) one layer up. Keeping the
 * service edition-agnostic lets fixtures / Pest exercise it directly.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ApiTokenService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @var int the number of random characters in a freshly-minted token.
     *     32 chars of `generateRandomString()` alphabet (~190 bits) — well
     *     beyond brute-force reach while staying copy-paste friendly.
     */
    public const TOKEN_LENGTH = 32;

    /**
     * @var int the number of leading characters stored as the display
     *     prefix. Eight is enough to disambiguate tokens in the CP list
     *     without narrowing the keyspace meaningfully.
     */
    public const PREFIX_LENGTH = 8;

    // Public Methods
    // =========================================================================

    /**
     * Issues a new API token. Generates a CSPRNG-backed plaintext, persists
     * only its SHA-256 hash + display prefix, and returns the plaintext
     * exactly once alongside the stored model.
     *
     * @param string $name a human-readable label for the token
     * @param string[]|null $scopes optional scope list (reserved for future
     *     per-endpoint scoping; null = full read access)
     * @param DateTime|null $expiresAt optional expiry; null = no expiry
     * @return array{token: string, model: ApiTokenModel} the plaintext token
     *     (shown once) and the stored model (carries no secret)
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function issue(string $name, ?array $scopes = null, ?DateTime $expiresAt = null): array
    {
        $plaintext = Craft::$app->getSecurity()->generateRandomString(self::TOKEN_LENGTH);
        $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

        $record = new ApiTokenRecord();
        $record->name = $name;
        $record->tokenHash = $this->_hash($plaintext);
        $record->tokenPrefix = substr($plaintext, 0, self::PREFIX_LENGTH);
        $record->scopes = ($scopes !== null && $scopes !== []) ? Json::encode(array_values($scopes)) : null;
        $record->lastUsedAt = null;
        $record->expiresAt = $expiresAt?->format('Y-m-d H:i:s');
        $record->createdByUserId = Craft::$app->getUser()->getId();
        $record->dateCreated = $now;
        $record->dateUpdated = $now;
        $record->uid = StringHelper::UUID();
        $record->save(false);

        return [
            'token' => $plaintext,
            'model' => ApiTokenModel::fromRecord($record),
        ];
    }

    /**
     * Resolves a plaintext token to its model, or `null` when the token
     * doesn't exist OR has expired. On a successful resolve, touches
     * `lastUsedAt` so the CP list can surface last-use recency.
     *
     * Expiry and non-existence both return `null` so the caller returns a
     * uniform 401 — no existence oracle. The final compare is constant-time
     * via `hash_equals()`.
     *
     * @param string $plaintext the candidate Bearer token
     * @return ApiTokenModel|null the resolved model, or null on miss/expiry
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function findByToken(#[\SensitiveParameter] string $plaintext): ?ApiTokenModel
    {
        if ($plaintext === '') {
            return null;
        }

        $hash = $this->_hash($plaintext);
        $record = ApiTokenRecord::findOne(['tokenHash' => $hash]);

        if ($record === null) {
            return null;
        }

        // Constant-time confirm on the resolved row. The unique-index
        // lookup already pinned the row, but the explicit `hash_equals`
        // keeps the accept path timing-uniform and documents the contract.
        if (!hash_equals((string)$record->tokenHash, $hash)) {
            return null;
        }

        // Reject expired tokens — uniform null with the not-found path.
        if ($record->expiresAt !== null && Carbon::parse($record->expiresAt, 'UTC')->isPast()) {
            return null;
        }

        $record->lastUsedAt = Carbon::now('UTC')->format('Y-m-d H:i:s');
        $record->save(false, ['lastUsedAt', 'dateUpdated']);

        return ApiTokenModel::fromRecord($record);
    }

    /**
     * Returns every issued token, most-recently-created first. Carries no
     * secrets — the models never hold `tokenHash`.
     *
     * @return ApiTokenModel[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAllTokens(): array
    {
        /** @var ApiTokenRecord[] $records */
        $records = ApiTokenRecord::find()
            ->orderBy(['dateCreated' => SORT_DESC])
            ->all();

        return array_map(
            static fn(ApiTokenRecord $record): ApiTokenModel => ApiTokenModel::fromRecord($record),
            $records,
        );
    }

    /**
     * Returns a single token model by primary key, or null when absent.
     *
     * @param int $id
     * @return ApiTokenModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTokenById(int $id): ?ApiTokenModel
    {
        $record = ApiTokenRecord::findOne(['id' => $id]);

        return $record !== null ? ApiTokenModel::fromRecord($record) : null;
    }

    /**
     * Revokes (deletes) a token by primary key. Returns true when a row was
     * deleted, false when no row matched.
     *
     * @param int $id
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function revoke(int $id): bool
    {
        $record = ApiTokenRecord::findOne(['id' => $id]);

        if ($record === null) {
            return false;
        }

        return (bool)$record->delete();
    }

    /**
     * Prunes every token whose `expiresAt` is in the past. Idempotent —
     * safe to call from `gc/run` cron repeatedly. Tokens with a null
     * `expiresAt` (no-expiry) are never pruned.
     *
     * @return int the number of rows deleted
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function pruneExpired(): int
    {
        $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

        return Craft::$app->getDb()->createCommand()
            ->delete(
                '{{%passwordpolicy_api_tokens}}',
                ['and', ['not', ['expiresAt' => null]], ['<', 'expiresAt', $now]],
            )
            ->execute();
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the SHA-256 hex digest of a plaintext token — the value
     * persisted as `tokenHash` and the lookup key on `findByToken()`.
     *
     * SHA-256 (not bcrypt/argon) is the right primitive here: API tokens are
     * high-entropy CSPRNG strings, not low-entropy human passwords, so the
     * slow-hash defense against dictionary attacks buys nothing — while a
     * fast digest keeps the per-request auth lookup cheap and lets the
     * column carry a unique index.
     *
     * @param string $plaintext
     * @return string the 64-char lowercase hex digest
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hash(#[\SensitiveParameter] string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }
}
