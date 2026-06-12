<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\records;

use craft\db\ActiveRecord;
use craft\records\Element;
use yii\db\ActiveQueryInterface;

/**
 * Class AuditLogRecord
 *
 * Active-record wrapper around `passwordpolicy_audit_log`. The table
 * is element-backed (Craft 5 idiom, Step 5 refactor): `id` is a FK to
 * `craft_elements.id` with `ON DELETE CASCADE`. The record stays the
 * storage layer; the queryable + index surface lives on
 * {@see \craftpulse\passwordpolicy\elements\AuditLogElement}.
 *
 * **Chain bytes unchanged.** `rowHash`, `previousHash`, and the
 * canonical payload that produces them are identical to the
 * pre-element shape. Element-ification only changed the row's
 * identifier provenance (auto-increment → `craft_elements.id`); the
 * `id` column is NOT part of the canonical payload, so every existing
 * chain hash continues to verify byte-identically.
 *
 * **userId outlives the user.** Nullable + `SET NULL` on user hard-
 * delete so the audit row outlives the entity, per
 * `project_audit_capture_principle.md`. `changedByUserId` follows the
 * same pattern.
 *
 * @property int $id matches `craft_elements.id`
 * @property ?int $userId nullable — `SET NULL` on user hard-delete
 * @property ?int $changedByUserId nullable — `SET NULL` on user hard-delete
 * @property string $event
 * @property string $outcome
 * @property ?string $source
 * @property ?array $details
 * @property ?string $ipHash
 * @property ?string $userIdentifier HMAC of the subject's email — hashed identity (the FK `userId` is not)
 * @property ?string $changedByIdentifier HMAC of the actor's email — hashed identity (the FK `changedByUserId` is not)
 * @property ?string $geoCountry ISO 3166-1 alpha-2 country code — excluded from the canonical hash payload
 * @property ?string $geoRegion subdivision/region name — excluded from the canonical hash payload
 * @property string $rowHash sha256(canonicalize(payload) . previousHash)
 * @property string $previousHash sha256 of prior row's rowHash (or genesis sentinel)
 * @property ?string $forwardedAt SIEM forwarder writeback — NULL = unforwarded
 * @property int $forwardAttempts SIEM forwarder retry counter
 * @property string $dateCreated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditLogRecord extends ActiveRecord
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function tableName(): string
    {
        return '{{%passwordpolicy_audit_log}}';
    }

    /**
     * Relation back to the paired `craft_elements` row.
     *
     * @return ActiveQueryInterface
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getElement(): ActiveQueryInterface
    {
        return $this->hasOne(Element::class, ['id' => 'id']);
    }
}
