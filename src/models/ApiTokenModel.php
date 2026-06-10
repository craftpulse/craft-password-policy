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
use craftpulse\passwordpolicy\records\ApiTokenRecord;
use DateTime;

/**
 * Class ApiTokenModel
 *
 * Transport model for a row in `passwordpolicy_api_tokens`. Pairs with
 * {@see ApiTokenRecord} — the read surfaces in
 * {@see \craftpulse\passwordpolicy\services\ApiTokenService} hydrate models
 * from records so callers never touch ActiveRecord datetime-string quirks.
 *
 * **Security: the `tokenHash` column is deliberately NOT a property on this
 * model.** It never leaves the service layer — the model carries only the
 * non-secret display fields (`name`, `tokenPrefix`, timestamps, scopes), so
 * a model serialised into any CP template or API JSON response can never
 * leak the hash. {@see fields()} additionally pins the serialisation
 * allowlist so a future property addition can't accidentally widen it.
 *
 * Datetime columns come back from ActiveRecord as raw strings;
 * `fromRecord()` hydrates them via `DateTimeHelper::toDateTime()` per the
 * project idiom (direct assignment to `?DateTime` properties throws on a
 * string).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ApiTokenModel extends Model
{
    // Static Methods
    // =========================================================================

    /**
     * Builds a model from a record, hydrating datetime strings into
     * `?DateTime` instances. The `tokenHash` column is intentionally NOT
     * read across — it never reaches the model layer.
     *
     * @param ApiTokenRecord $record
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRecord(ApiTokenRecord $record): self
    {
        $model = new self();
        $model->id = (int)$record->id;
        $model->name = (string)$record->name;
        $model->tokenPrefix = (string)$record->tokenPrefix;
        $model->scopes = self::_decodeScopes($record->scopes);
        $model->lastUsedAt = $record->lastUsedAt !== null
            ? (DateTimeHelper::toDateTime($record->lastUsedAt) ?: null)
            : null;
        $model->expiresAt = $record->expiresAt !== null
            ? (DateTimeHelper::toDateTime($record->expiresAt) ?: null)
            : null;
        $model->createdByUserId = $record->createdByUserId !== null ? (int)$record->createdByUserId : null;
        $model->dateCreated = DateTimeHelper::toDateTime($record->dateCreated) ?: null;
        $model->dateUpdated = DateTimeHelper::toDateTime($record->dateUpdated) ?: null;
        $model->uid = (string)$record->uid;

        return $model;
    }

    // Public Properties
    // =========================================================================

    /**
     * @var int|null the user who issued the token, or null once that user
     *     is deleted (FK SET NULL).
     */
    public ?int $createdByUserId = null;

    /**
     * @var DateTime|null when the row was created.
     */
    public ?DateTime $dateCreated = null;

    /**
     * @var DateTime|null when the row was last updated.
     */
    public ?DateTime $dateUpdated = null;

    /**
     * @var DateTime|null when the token expires, or null for no expiry.
     */
    public ?DateTime $expiresAt = null;

    /**
     * @var int|null primary key.
     */
    public ?int $id = null;

    /**
     * @var DateTime|null when the token was last used to authenticate a
     *     request, or null if never used.
     */
    public ?DateTime $lastUsedAt = null;

    /**
     * @var string|null human-readable label for the token.
     */
    public ?string $name = null;

    /**
     * @var string[]|null optional scope list (reserved for future
     *     per-endpoint scoping; null = full read access).
     */
    public ?array $scopes = null;

    /**
     * @var string|null the first 8 chars of the plaintext token, stored
     *     for CP display/identification. Never the full token.
     */
    public ?string $tokenPrefix = null;

    /**
     * @var string|null UUID.
     */
    public ?string $uid = null;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Explicit serialisation allowlist. Pins the public shape so neither a
     * CP template nor an API JSON response can ever surface a secret —
     * there is no `tokenHash` property to expose, and this list guarantees
     * a future property addition stays opt-in.
     *
     * @return array<int, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function fields(): array
    {
        return [
            'id',
            'name',
            'tokenPrefix',
            'scopes',
            'lastUsedAt',
            'expiresAt',
            'createdByUserId',
            'dateCreated',
            'dateUpdated',
            'uid',
        ];
    }

    // Private Methods
    // =========================================================================

    /**
     * Decodes the raw `scopes` column (JSON string, array, or null) into a
     * string list or null. Defensive against both string and pre-decoded
     * array inputs since ActiveRecord may hand back either depending on the
     * driver's JSON handling.
     *
     * @param mixed $raw
     * @return string[]|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _decodeScopes(mixed $raw): ?array
    {
        if ($raw === null || $raw === '') {
            return null;
        }

        if (is_array($raw)) {
            return array_values(array_map('strval', $raw));
        }

        $decoded = json_decode((string)$raw, true);

        if (!is_array($decoded)) {
            return null;
        }

        return array_values(array_map('strval', $decoded));
    }
}
