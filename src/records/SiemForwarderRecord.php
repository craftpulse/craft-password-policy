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
 * registry of syslog-over-TLS endpoints the plugin forwards audit-log
 * rows to (G8).
 *
 * @property int $id
 * @property string|null $name
 * @property string $protocol
 * @property string $host
 * @property int $port
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
