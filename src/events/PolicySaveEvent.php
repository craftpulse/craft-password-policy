<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\events;

use craftpulse\passwordpolicy\models\PolicyModel;
use yii\base\ModelEvent;

/**
 * Class PolicySaveEvent
 *
 * Fired by `PolicyService::savePolicy()` around the policy-save lifecycle.
 * The same event class is shared between `EVENT_BEFORE_SAVE_POLICY` and
 * `EVENT_AFTER_SAVE_POLICY` — listeners distinguish the two phases by which
 * constant they subscribed to and (where it matters) by `$isNew`.
 *
 * Veto contract
 * -------------
 * Extends `\yii\base\ModelEvent`, which exposes `public bool $isValid = true`.
 * On `EVENT_BEFORE_SAVE_POLICY`, a listener may flip `$event->isValid = false`
 * to abort the save — `savePolicy()` returns `false` and no DB writes occur.
 * Matches the canonical Craft / Yii idiom (`Element::EVENT_BEFORE_SAVE`).
 *
 * `EVENT_AFTER_SAVE_POLICY` listeners cannot abort: by the time it fires the
 * transaction is already committed. The `$isValid` flag is inherited but
 * meaningless after-the-fact.
 *
 * `$isNew` semantics
 * ------------------
 * Reflects the PRE-save shape of the policy (`policy->id === null` at the
 * moment `savePolicy()` was invoked). On `EVENT_BEFORE_SAVE_POLICY` the
 * model's `id` is null when `$isNew === true`; on
 * `EVENT_AFTER_SAVE_POLICY` the auto-increment will have populated
 * `policy->id` even when `$isNew === true`, so listeners that need to
 * branch on "newly created vs updated existing" use `$isNew` rather than
 * a fresh null check.
 *
 * @event PolicySaveEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicySaveEvent extends ModelEvent
{
    // Public Properties
    // =========================================================================

    /**
     * @var int[] the user-group IDs the caller passed to `savePolicy()`. The
     *     array is mutable on `EVENT_BEFORE_SAVE_POLICY` — listeners can
     *     adjust the assignment before the junction-table sync runs.
     *     Read-only in spirit on `EVENT_AFTER_SAVE_POLICY` (mutation has no
     *     downstream effect because the junction sync has already run).
     */
    public array $groupIds = [];

    /**
     * @var bool whether the save was an INSERT (true) or UPDATE (false). The
     *     value reflects the pre-save shape of the policy and is consistent
     *     across `EVENT_BEFORE_SAVE_POLICY` and `EVENT_AFTER_SAVE_POLICY` —
     *     even though `policy->id` will be populated by AFTER_SAVE for
     *     INSERTs, `$isNew` still reads `true` so listeners can branch on
     *     "newly created" without re-deriving it.
     */
    public bool $isNew = false;

    /**
     * @var PolicyModel the policy being saved. Mutable on
     *     `EVENT_BEFORE_SAVE_POLICY` — a listener may amend fields and the
     *     amended model is what `savePolicy()` will persist. On
     *     `EVENT_AFTER_SAVE_POLICY` the model reflects the just-committed
     *     state (`id` populated for INSERTs, `dateUpdated` refreshed).
     */
    public PolicyModel $policy;
}
