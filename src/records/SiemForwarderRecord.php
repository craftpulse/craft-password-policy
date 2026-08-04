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
 * Class SiemForwarderRecord
 *
 * ActiveRecord for the `passwordpolicy_siem_forwarders` table — the
 * registry of destinations the plugin forwards audit-log rows to (G8).
 *
 * `protocol` decides which half of the row is in use: `syslog-tls` uses
 * `host` + `port` + `framing` + the two `tls*` columns, `http` uses
 * `url` + `authType` + `authToken` + `headers`. All three address columns
 * are therefore nullable, and `SiemForwarderModel` requires each one
 * conditionally on the protocol.
 *
 * `authToken` holds base64-wrapped ciphertext, never a plaintext
 * credential. The encryption boundary is
 * {@see \craftpulse\passwordpolicy\models\SiemForwarderModel}.
 *
 * @property int $id
 * @property string|null $name
 * @property string $protocol
 * @property string|null $host
 * @property int|null $port
 * @property string|null $url
 * @property string $authType
 * @property string|null $authToken
 * @property array|null $headers
 * @property string $framing
 * @property bool $tlsCertVerify
 * @property string|null $tlsCaBundlePath
 * @property array|null $eventClasses
 * @property bool $enabled
 * @property \DateTime|null $circuitOpenAt
 * @property int $consecutiveFailures
 * @property \DateTime $dateCreated
 * @property \DateTime $dateUpdated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SiemForwarderRecord extends ActiveRecord
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
        return '{{%passwordpolicy_siem_forwarders}}';
    }
}
