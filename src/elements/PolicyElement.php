<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements;

use Craft;
use craft\base\Element;
use craft\db\Query;
use craft\elements\actions\Delete;
use craft\elements\actions\Restore;
use craft\elements\User;
use craft\helpers\Cp;
use craft\helpers\Html;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craft\helpers\UrlHelper;
use craftpulse\passwordpolicy\elements\db\PolicyQuery;
use craftpulse\passwordpolicy\enums\PolicyPreset;
use craftpulse\passwordpolicy\events\PolicySaveEvent;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\PolicyRecord;
use Exception;
use Throwable;
use yii\base\InvalidArgumentException;

/**
 * Class PolicyElement
 *
 * Craft element wrapper around `passwordpolicy_policies`. Pairs with
 * {@see PolicyRecord} (storage) and {@see PolicyModel} (validation +
 * legacy carrier): the element provides the queryable + index surface,
 * the record stays the storage layer, the model continues to carry
 * validation rules + form-binding shape that existing CP controllers
 * + tests rely on. Element id IS record id IS `craft_elements.id`.
 *
 * **Tri-layer storage pairing.** Why all three are kept rather than
 * collapsed to two:
 *  - PolicyModel — `defineRules()` + env-attribute parser + tri-state
 *    semantics + the in-memory shape `PolicyResolverService` /
 *    `GroupPolicyModel::mergeWithGlobal()` consume. Replacing wholesale
 *    would balloon the diff for no benefit; the model is the contract
 *    every downstream consumer reads.
 *  - PolicyElement — queryable / indexable surface, condition rules,
 *    element actions. The "outer" surface CP users + third-party
 *    integrations interact with.
 *  - PolicyRecord — ActiveRecord persistence. Matches the Step 4 / Step
 *    5 / Formie pattern.
 *
 * `PolicyService` translates Model ↔ Element ↔ Record. The Model is
 * the validation surface; the Element is the persistence surface; the
 * Record is the storage layer.
 *
 * **PolicySaveEvent contract preserved.** `PolicyService::savePolicy()`
 * continues to fire `EVENT_BEFORE_SAVE_POLICY` (with veto contract) and
 * `EVENT_AFTER_SAVE_POLICY` around the element-pipeline save call. The
 * event payload remains `(PolicyModel $policy, array $groupIds)` — the
 * third-party listener surface is unchanged. The element exists below
 * the service-level event surface.
 *
 * **G4 audit-diff lives in element afterSave().** The pre-save state
 * capture moves to `beforeSave()` (loads the existing policy + group
 * IDs from disk before the upsert overwrites them); the diff
 * computation + `policy_changed` event fire moves to `afterSave()`.
 * Inline implementation that lived in `PolicyService::savePolicy()`
 * is gone — the service slims down. Per the durable invariant,
 * audit-write hiccups never unwind the saved policy: the audit fire
 * is wrapped in try/catch.
 *
 * **Junction sync runs in afterSave().** The transient `$groupIds`
 * array is the element's escape hatch for the assigned-groups
 * synchronisation. Setters (PolicyService, future third-party
 * persisters) populate it on the element before save; `afterSave()`
 * deletes existing junction rows and re-inserts. CASCADE on
 * `policy_groups.policyId → policies.id` cleans up if the element is
 * hard-deleted.
 *
 * **Statuses.** `enabled` is the only active status for 5.2.0. The
 * `disabled` slot is reserved for a future "soft-disable a named
 * policy without deleting it" UX — leaving it on the statuses() map
 * documents intent without making it routable today.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PolicyElement extends Element
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int>|null transient assigned-group IDs that
     *     `afterSave()` syncs into `passwordpolicy_policy_groups`. Set
     *     by callers (`PolicyService::savePolicy()`) before saving the
     *     element. NULL means "leave the junction alone" (read-only
     *     persist via the element pipeline); `[]` means "remove all
     *     assignments." Not persisted on the element.
     */
    public ?array $groupIds = null;

    /**
     * @var ?string the policy handle (unique identifier)
     */
    public ?string $handle = null;

    /**
     * @var ?string the human-readable policy name
     */
    public ?string $name = null;

    /**
     * @var ?string the preset this policy was derived from (e.g.
     *     `nist-800-63b`); null when the policy is a fully-custom build
     */
    public ?string $preset = null;

    /**
     * @var array<string, mixed>|string|null override fields for this
     *     policy as decoded JSON. The raw JSON column populates this
     *     property as either a string (driver-dependent) or an array;
     *     `init()` normalises to array. NULL means "no overrides
     *     stored" — every field inherits from global settings.
     */
    public array|string|null $settings = null;

    /**
     * @var int the sort order for policy precedence among multiple
     *     applicable policies
     */
    public int $sortOrder = 0;

    // Private Properties
    // =========================================================================

    /**
     * @var array{
     *     name: ?string,
     *     handle: ?string,
     *     preset: ?string,
     *     sortOrder: int,
     *     settings: array<string, mixed>,
     *     groupIds: int[]
     * }|null pre-save snapshot of the on-disk row + junction state.
     *     `beforeSave()` captures; `afterSave()` consumes to compute
     *     the G4 `policy_changed` diff. NULL on INSERTs (nothing to
     *     diff against).
     */
    private ?array $_preSaveSnapshot = null;

    // Static Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function displayName(): string
    {
        return Craft::t('password-policy', 'Password Policy');
    }

    /**
     * @inheritdoc
     *
     * @return PolicyQuery
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function find(): PolicyQuery
    {
        return new PolicyQuery(static::class);
    }

    /**
     * Hydrates a `PolicyElement` from a `PolicyModel` and the caller-
     * supplied `$groupIds`. Used by `PolicyService::savePolicy()` to
     * translate the model into the element-pipeline payload. New-policy
     * vs existing-policy is resolved by the caller — when
     * `$model->id !== null` we load the existing element so the
     * pipeline's UPDATE branch runs; otherwise a fresh element drops
     * onto the INSERT branch.
     *
     * Public on the element so third-party callers (e.g. data importers,
     * batch migrations) can build PolicyElement instances from existing
     * PolicyModel data without re-implementing the field-by-field copy.
     *
     * @param PolicyModel $model
     * @param int[] $groupIds
     * @return self
     *
     * @throws InvalidArgumentException when the model carries an id
     *     that doesn't resolve to a saved element (data-integrity check)
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromModel(PolicyModel $model, array $groupIds): self
    {
        if ($model->id !== null) {
            $element = self::find()->id($model->id)->one();
            if (!$element instanceof self) {
                throw new InvalidArgumentException(
                    "PolicyElement::fromModel called with PolicyModel id $model->id, but no matching element exists.",
                );
            }
        } else {
            $element = new self();
        }

        $element->name = $model->name;
        $element->handle = $model->handle;
        $element->preset = $model->preset;
        $element->sortOrder = $model->sortOrder;
        $element->settings = $model->getSettingsArray();
        $element->groupIds = array_map(static fn($id): int => (int)$id, $groupIds);

        return $element;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function hasStatuses(): bool
    {
        return true;
    }

    /**
     * @inheritdoc
     *
     * Single-site by design — policies apply across every site. Keeps
     * `passwordpolicy_policy_groups` unburdened by site context.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function isLocalized(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function lowerDisplayName(): string
    {
        return Craft::t('password-policy', 'password policy');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pluralDisplayName(): string
    {
        return Craft::t('password-policy', 'Password Policies');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pluralLowerDisplayName(): string
    {
        return Craft::t('password-policy', 'password policies');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function refHandle(): ?string
    {
        return 'policy';
    }

    /**
     * @inheritdoc
     *
     * Every saved policy is `enabled` in 5.2.0. The `disabled` slot is
     * reserved for a future soft-disable UX — leaving it on the map
     * documents intent without making it routable.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function statuses(): array
    {
        return [
            'enabled' => [
                'label' => Craft::t('password-policy', 'Enabled'),
                'color' => 'green',
            ],
            'disabled' => [
                'label' => Craft::t('password-policy', 'Disabled'),
                'color' => 'grey',
            ],
        ];
    }

    // Protected Static Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Delete + Restore. Edit lands on the existing CP edit screen
     * (`password-policy/policies/<id>`) — `cpEditUrl()` points at it.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineActions(string $source = null): array
    {
        return [
            [
                'type' => Delete::class,
                'confirmationMessage' => Craft::t(
                    'password-policy',
                    'Are you sure you want to delete the selected policies? Group assignments will be removed.',
                ),
                'successMessage' => Craft::t('password-policy', 'Policies deleted.'),
            ],
            [
                'type' => Restore::class,
                'successMessage' => Craft::t('password-policy', 'Policies restored.'),
                'partialSuccessMessage' => Craft::t('password-policy', 'Some policies restored.'),
                'failMessage' => Craft::t('password-policy', 'Policies not restored.'),
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineDefaultTableAttributes(string $source): array
    {
        return ['handle', 'preset', 'dateUpdated'];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSearchableAttributes(): array
    {
        return ['name', 'handle'];
    }

    /**
     * @inheritdoc
     *
     * `All` source only. Per-preset and per-group sidebar sources are
     * additive enhancements that can layer on in 5.3 without touching
     * this shape.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSources(string $context = null): array
    {
        return [
            [
                'key' => '*',
                'label' => Craft::t('password-policy', 'All policies'),
                'criteria' => [],
                'defaultSort' => ['sortOrder', 'asc'],
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineSortOptions(): array
    {
        return [
            [
                'label' => Craft::t('password-policy', 'Name'),
                'orderBy' => 'passwordpolicy_policies.name',
                'attribute' => 'name',
            ],
            [
                'label' => Craft::t('password-policy', 'Handle'),
                'orderBy' => 'passwordpolicy_policies.handle',
                'attribute' => 'handle',
            ],
            [
                'label' => Craft::t('password-policy', 'Sort order'),
                'orderBy' => 'passwordpolicy_policies.sortOrder',
                'attribute' => 'sortOrder',
                'defaultDir' => 'asc',
            ],
            [
                'label' => Craft::t('password-policy', 'Last updated'),
                'orderBy' => 'passwordpolicy_policies.dateUpdated',
                'attribute' => 'dateUpdated',
                'defaultDir' => 'desc',
            ],
        ];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected static function defineTableAttributes(): array
    {
        return [
            'name' => ['label' => Craft::t('password-policy', 'Name')],
            'handle' => ['label' => Craft::t('password-policy', 'Handle')],
            'preset' => ['label' => Craft::t('password-policy', 'Preset')],
            'sortOrder' => ['label' => Craft::t('password-policy', 'Order')],
            'dateUpdated' => ['label' => Craft::t('password-policy', 'Last updated')],
            'dateCreated' => ['label' => Craft::t('password-policy', 'Created')],
        ];
    }

    // Public Methods
    // =========================================================================

    /**
     * Persists the paired `PolicyRecord` AND syncs the
     * `passwordpolicy_policy_groups` junction AND fires the G4
     * `policy_changed` audit diff. Element id IS record id IS
     * `craft_elements.id`.
     *
     * The pre-save snapshot captured in `beforeSave()` feeds the G4
     * diff comparison. INSERTs have no pre-state and never fire the
     * diff event (a future `policy_created` event class is out of
     * scope per G4).
     *
     * Audit fire is wrapped in try/catch — the parent transaction is
     * already committed by the time we reach the diff path, so an
     * audit-write hiccup must never unwind the saved policy.
     *
     * @inheritdoc
     *
     * @throws Exception when the record is unexpectedly missing on an
     *     update (corruption indicator)
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function afterSave(bool $isNew): void
    {
        $this->_upsertRecord($isNew);

        if ($this->groupIds !== null) {
            $this->_syncGroupIds($this->groupIds);
        }

        if (!$isNew && $this->_preSaveSnapshot !== null) {
            $this->_fireDiffEvent();
        }

        parent::afterSave($isNew);
    }

    /**
     * Captures the on-disk policy state BEFORE the element save
     * overwrites it. Drives the G4 `policy_changed` audit-diff capture
     * in `afterSave()`.
     *
     * INSERTs skip the snapshot — there's nothing to diff against and
     * the `policy_changed` event is UPDATE-only.
     *
     * Loads via direct queries (not `PolicyService::getPolicyById()`)
     * to avoid re-entering the service layer during an in-flight save.
     *
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeSave(bool $isNew): bool
    {
        if (!$isNew && $this->id !== null) {
            $this->_preSaveSnapshot = $this->_loadPreSaveSnapshot();
        }

        return parent::beforeSave($isNew);
    }

    /**
     * @inheritdoc
     *
     * Admin-only — keeps the CP element-index Delete action consistent
     * with the existing `PolicyController::actionDelete` permission
     * check.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canDelete(User $user): bool
    {
        if ($user->admin) {
            return true;
        }

        return $user->can(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
    }

    /**
     * @inheritdoc
     *
     * Mirrors the existing `PolicyController::beforeAction()` gate:
     * admin OR {@see PasswordPolicy::PERMISSION_MANAGE_SETTINGS}.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canSave(User $user): bool
    {
        if ($user->admin) {
            return true;
        }

        return $user->can(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canView(User $user): bool
    {
        if ($user->admin) {
            return true;
        }

        return $user->can(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
    }

    /**
     * @inheritdoc
     *
     * `enabled` for every saved policy. The `disabled` slot is reserved
     * for a future soft-disable UX (not active in 5.2.0).
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStatus(): ?string
    {
        return 'enabled';
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUiLabel(): string
    {
        return $this->name ?? Craft::t('password-policy', 'Policy');
    }

    /**
     * Hydrates the `settings` JSON column on read. Yii's JSON
     * ColumnSchema decodes JSON columns through `phpTypecast()`, but
     * the element-pipeline population path doesn't always route through
     * that — a leftover string surfaces driver-dependent. Normalise
     * here to a stable shape so downstream consumers
     * (`PolicyModel::fromElement()`, table-attribute renderer) read
     * predictable types. Double-decode handles legacy upgrade-path
     * rows that wrote `json_encode(json_encode($settings))`.
     *
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function init(): void
    {
        parent::init();

        if (is_string($this->settings)) {
            $decoded = Json::decodeIfJson($this->settings);

            if (is_string($decoded)) {
                $decoded = Json::decodeIfJson($decoded);
            }

            $this->settings = is_array($decoded) ? $decoded : null;
        }
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function attributeHtml(string $attribute): string
    {
        switch ($attribute) {
            case 'name':
                return $this->name !== null ? Html::encode($this->name) : '';

            case 'handle':
                return $this->handle !== null
                    ? Html::tag('code', Html::encode($this->handle))
                    : '';

            case 'preset':
                if ($this->preset === null) {
                    return Html::tag('span', Craft::t('password-policy', 'Custom'), [
                        'class' => 'light',
                    ]);
                }

                $enum = PolicyPreset::tryFrom($this->preset);
                $label = $enum !== null ? $enum->label() : $this->preset;

                return Cp::statusLabelHtml([
                    'color' => 'blue',
                    'label' => $label,
                ]);

            case 'sortOrder':
                return Html::tag('span', (string)$this->sortOrder, ['class' => 'rightalign']);
        }

        return parent::attributeHtml($attribute);
    }

    /**
     * @inheritdoc
     *
     * The CP edit screen lives at `/admin/password-policy/policies/<id>`
     * — the existing `PolicyController::actionEdit` route. Returning the
     * URL here means `Cp::elementChipHtml()` and the element-index "Edit"
     * link route through the same controller that handles direct subnav
     * navigation.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function cpEditUrl(): ?string
    {
        if ($this->id === null) {
            return null;
        }

        return UrlHelper::cpUrl('password-policy/policies/' . $this->id);
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds the field-level `{field: {old, new}}` diff for the
     * `policy_changed` audit event, using the pre-save snapshot
     * captured in `beforeSave()` and the current element state.
     *
     * Compared surfaces:
     *
     *  - Top-level columns: `name`, `handle`, `preset`, `sortOrder`.
     *  - Every key in `PolicyModel::settingsFields()` — sourced from the
     *    settings JSON column on both sides so null (inherit) values
     *    normalise.
     *  - `groupIds` — the assigned-groups junction. Sorted (numeric
     *    ascending) before comparison; group order is not semantic.
     *
     * Unchanged fields are omitted entirely; an empty diff means the
     * caller skips the audit write.
     *
     * @return array<string, array{old: mixed, new: mixed}>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildDiff(): array
    {
        if ($this->_preSaveSnapshot === null) {
            return [];
        }

        $snapshot = $this->_preSaveSnapshot;
        $currentSettings = is_array($this->settings) ? $this->settings : [];
        $currentGroupIds = $this->groupIds ?? $snapshot['groupIds'];

        $diff = [];

        // Top-level columns
        $topLevel = [
            'name' => [$snapshot['name'], $this->name],
            'handle' => [$snapshot['handle'], $this->handle],
            'preset' => [$snapshot['preset'], $this->preset],
            'sortOrder' => [(int)$snapshot['sortOrder'], (int)$this->sortOrder],
        ];

        foreach ($topLevel as $field => [$old, $new]) {
            if ($old !== $new) {
                $diff[$field] = ['old' => $old, 'new' => $new];
            }
        }

        // Settings array — walk the canonical list, pulling each value
        // from the snapshot + current arrays. Explicit null (inherit)
        // values participate in the diff so a "turn off override"
        // transition lands as a diff entry rather than silently dropped.
        foreach (PolicyModel::settingsFields() as $field) {
            $oldValue = $snapshot['settings'][$field] ?? null;
            $newValue = $currentSettings[$field] ?? null;

            if ($oldValue !== $newValue) {
                $diff[$field] = ['old' => $oldValue, 'new' => $newValue];
            }
        }

        // Group assignments. Sort both ascending — group order is not
        // semantic, swapping rows around in the junction table should
        // not produce a diff.
        $oldGroupIds = array_map(static fn($id): int => (int)$id, $snapshot['groupIds']);
        $newGroupIds = array_map(static fn($id): int => (int)$id, $currentGroupIds);
        sort($oldGroupIds, SORT_NUMERIC);
        sort($newGroupIds, SORT_NUMERIC);

        if ($oldGroupIds !== $newGroupIds) {
            $diff['groupIds'] = ['old' => $oldGroupIds, 'new' => $newGroupIds];
        }

        return $diff;
    }

    /**
     * Fires the `policy_changed` audit event for a successful UPDATE.
     *
     * Wrapped in try/catch — the element save is already committed at
     * this point, and an audit-write failure must never unwind a saved
     * policy. AuditLogService internally fail-safes its own writes,
     * but the wrapping catch is belt-and-braces against any future
     * change to that contract.
     *
     * `userId` is null because the event subject is the policy itself,
     * not a user. The audit row's `changedByUserId` is auto-resolved
     * from the current admin context inside `AuditLogService::logEvent()`.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _fireDiffEvent(): void
    {
        $diff = $this->_buildDiff();

        if (empty($diff)) {
            return;
        }

        try {
            PasswordPolicy::$plugin->getAuditLog()->logEvent(
                userId: null,
                event: 'policy_changed',
                details: [
                    'diff' => $diff,
                    'policyId' => (int)$this->id,
                    'policyName' => $this->name,
                ],
            );
        } catch (Throwable $e) {
            Craft::error(
                'Failed to write policy_changed audit event: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Loads the on-disk row + junction assignments for this element's
     * id, shaped for the G4 `policy_changed` diff. One row-query +
     * one junction-column-query, the minimum needed for the diff
     * comparison.
     *
     * Handles the same JSON string-or-array driver variability that
     * `init()` deals with — `beforeSave()` runs before `init()` has
     * touched the new payload, so the snapshot reads what's on disk.
     * The double-decode handles legacy upgrade-path rows that wrote
     * `json_encode(json_encode($settings))`.
     *
     * Direct queries (not `PolicyService::getPolicyById()`) so we don't
     * re-enter the service layer during an in-flight save.
     *
     * @return array{
     *     name: ?string,
     *     handle: ?string,
     *     preset: ?string,
     *     sortOrder: int,
     *     settings: array<string, mixed>,
     *     groupIds: int[]
     * }
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _loadPreSaveSnapshot(): array
    {
        $row = (new Query())
            ->select(['name', 'handle', 'preset', 'sortOrder', 'settings'])
            ->from('{{%passwordpolicy_policies}}')
            ->where(['id' => $this->id])
            ->one() ?: [];

        $settings = $row['settings'] ?? null;

        if (is_string($settings)) {
            $decoded = Json::decodeIfJson($settings);

            if (is_string($decoded)) {
                $decoded = Json::decodeIfJson($decoded);
            }

            $settings = is_array($decoded) ? $decoded : [];
        }

        if (!is_array($settings)) {
            $settings = [];
        }

        $groupIds = array_map(
            static fn($id): int => (int)$id,
            (new Query())
                ->select(['groupId'])
                ->from('{{%passwordpolicy_policy_groups}}')
                ->where(['policyId' => $this->id])
                ->column(),
        );

        return [
            'name' => $row['name'] ?? null,
            'handle' => $row['handle'] ?? null,
            'preset' => $row['preset'] ?? null,
            'sortOrder' => (int)($row['sortOrder'] ?? 0),
            'settings' => $settings,
            'groupIds' => $groupIds,
        ];
    }

    /**
     * Syncs the `passwordpolicy_policy_groups` junction to the
     * `$groupIds` array. Replaces every existing junction row for this
     * policy.
     *
     * @param int[] $groupIds
     * @return void
     *
     * @throws \yii\db\Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _syncGroupIds(array $groupIds): void
    {
        $db = Craft::$app->getDb();
        $now = (new \DateTime())->format('Y-m-d H:i:s');

        $db->createCommand()
            ->delete('{{%passwordpolicy_policy_groups}}', ['policyId' => $this->id])
            ->execute();

        foreach ($groupIds as $groupId) {
            $db->createCommand()
                ->insert('{{%passwordpolicy_policy_groups}}', [
                    'policyId' => $this->id,
                    'groupId' => (int)$groupId,
                    'dateCreated' => $now,
                    'dateUpdated' => $now,
                    'uid' => StringHelper::UUID(),
                ])
                ->execute();
        }
    }

    /**
     * Inserts (on `$isNew = true`) or updates (on `$isNew = false`)
     * the paired `PolicyRecord`. Element id IS record id IS
     * `craft_elements.id` — the new record's id is set explicitly so
     * the FK to `craft_elements.id` holds.
     *
     * @param bool $isNew
     * @return void
     *
     * @throws Exception when the record is unexpectedly missing on an
     *     update (corruption indicator — the element row exists in
     *     `craft_elements` but no paired row was created in
     *     `passwordpolicy_policies`)
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _upsertRecord(bool $isNew): void
    {
        if ($isNew) {
            $record = new PolicyRecord();
            $record->id = (int)$this->id;
        } else {
            $record = PolicyRecord::findOne($this->id);

            if ($record === null) {
                throw new Exception('Invalid policy id: ' . $this->id);
            }
        }

        $record->name = $this->name ?? '';
        $record->handle = $this->handle ?? '';
        $record->preset = $this->preset;
        $record->settings = is_array($this->settings) ? $this->settings : [];
        $record->sortOrder = $this->sortOrder;

        // The `dateCreated` + `uid` on the element get propagated by
        // Craft's element pipeline to the matching columns. Mirror them
        // here so the paired record's columns stay aligned with the
        // craft_elements row.
        if ($this->dateCreated !== null) {
            $record->dateCreated = \craft\helpers\Db::prepareDateForDb($this->dateCreated);
        }

        if ($this->uid !== null && $this->uid !== '') {
            $record->uid = $this->uid;
        }

        $record->save(false);
    }
}
