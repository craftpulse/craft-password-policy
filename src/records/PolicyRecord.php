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

/**
 * Class PolicyRecord
 *
 * ActiveRecord wrapper around `passwordpolicy_policies`. Pairs with
 * {@see \craftpulse\passwordpolicy\elements\PolicyElement} (queryable
 * surface) and {@see \craftpulse\passwordpolicy\models\PolicyModel}
 * (validation surface). Record id IS element id IS `craft_elements.id`.
 *
 * Date columns are typed as `?string` because the element layer
 * propagates them via `Db::prepareDateForDb()` — assigning a
 * `DateTime` directly to the record would trigger Yii's column-cast
 * which expects the string form. The element's `init()` handles the
 * read-side decode for downstream consumers.
 *
 * @property int $id matches `craft_elements.id`
 * @property string $name
 * @property string $handle
 * @property string|null $preset
 * @property array $settings
 * @property int $sortOrder
 * @property string|null $dateCreated set by element pipeline via Db::prepareDateForDb
 * @property string|null $dateUpdated set by element pipeline via Db::prepareDateForDb
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyRecord extends ActiveRecord
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
        return '{{%passwordpolicy_policies}}';
    }
}
