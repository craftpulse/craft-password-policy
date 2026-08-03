<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\records;

use craft\db\ActiveRecord;

/**
 * Class WebhookEndpointRecord
 *
 * ActiveRecord for the `passwordpolicy_webhook_endpoints` table — the
 * registry of HTTP webhook subscribers the plugin POSTs HMAC-signed
 * audit payloads to (G9).
 *
 * The `secretCurrent` and `secretPrevious` columns store ciphertext;
 * the model layer handles the encrypt/decrypt round-trip via Craft's
 * `Security::encryptByKey()` / `decryptByKey()`. The Record surface
 * stays opaque — never decrypt at this layer; consumers always go
 * through the model.
 *
 * @property int $id
 * @property string|null $name
 * @property string $url
 * @property string $secretCurrent
 * @property string|null $secretPrevious
 * @property \DateTime|null $secretRotatedAt
 * @property array|null $eventClasses
 * @property bool $enabled
 * @property int|null $lastDeliveredRowId
 * @property int $consecutiveFailures
 * @property \DateTime|null $circuitOpenAt
 * @property \DateTime $dateCreated
 * @property \DateTime $dateUpdated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookEndpointRecord extends ActiveRecord
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
        return '{{%passwordpolicy_webhook_endpoints}}';
    }
}
