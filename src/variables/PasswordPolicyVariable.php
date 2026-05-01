<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\variables;

use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\twig\tags\LoginFormTag;
use craftpulse\passwordpolicy\twig\tags\PasswordChangeFormTag;
use craftpulse\passwordpolicy\twig\tags\PasswordFieldTag;
use craftpulse\passwordpolicy\twig\tags\PasswordResetFormTag;
use craftpulse\passwordpolicy\twig\tags\PasswordWidgetTag;
use craftpulse\passwordpolicy\twig\tags\RequirementListTag;
use craftpulse\passwordpolicy\twig\tags\RequirementsHintTag;
use craftpulse\passwordpolicy\twig\tags\StrengthMeterTag;
use DateTime;
use nystudio107\pluginvite\variables\ViteVariableInterface;
use nystudio107\pluginvite\variables\ViteVariableTrait;

/**
 * Class PasswordPolicyVariable
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
class PasswordPolicyVariable implements ViteVariableInterface
{
    use ViteVariableTrait;

    // Public Methods
    // =========================================================================

    /**
     * Returns the number of days until the current user's password expires.
     *
     * @return int|null null if no expiration configured or no user logged in
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function daysUntilExpiry(): ?int
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return null;
        }

        $expiryDate = $this->_getExpiryDate($user);

        if ($expiryDate === null) {
            return null;
        }

        $now = new DateTime();
        $diff = $now->diff($expiryDate);

        return $diff->invert ? 0 : $diff->days;
    }

    /**
     * Returns whether the current user's password is past expiration.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isExpired(): bool
    {
        $days = $this->daysUntilExpiry();

        return $days !== null && $days <= 0;
    }

    /**
     * Returns whether the current user's password expires within the given window.
     *
     * @param int $days
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isExpiring(int $days = 14): bool
    {
        $remaining = $this->daysUntilExpiry();

        if ($remaining === null) {
            return false;
        }

        return $remaining > 0 && $remaining <= $days;
    }

    /**
     * Returns the password status for the current user.
     *
     * @return string One of: current, expiring, expired, reset_required, never_changed, unknown
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function passwordStatus(): string
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return 'unknown';
        }

        if ($user->passwordResetRequired) {
            return 'reset_required';
        }

        if ($this->_getLastPasswordChangeDate($user) === null) {
            return 'never_changed';
        }

        if ($this->isExpired()) {
            return 'expired';
        }

        if ($this->isExpiring()) {
            return 'expiring';
        }

        return 'current';
    }

    /**
     * Returns the current user's last password change date.
     *
     * @return DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function lastPasswordChange(): ?DateTime
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return null;
        }

        return $this->_getLastPasswordChangeDate($user);
    }

    /**
     * Returns the number of active sessions for the current user.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function activeSessionCount(): int
    {
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return 0;
        }

        return (int)(new Query())
            ->from(Table::SESSIONS)
            ->where(['userId' => $user->id])
            ->count();
    }

    /**
     * Returns the resolved password policy as a flat associative array suitable
     * for Twig consumption.
     *
     * On Lite installs, always returns the global policy. On Pro installs:
     *  - When `params.groups` is provided (anonymous group preview), resolves
     *    against those group handles via PolicyResolverService's per-group
     *    merge.
     *  - When the current user has groups assigned, resolves for that user.
     *  - Otherwise returns global.
     *
     * Keys: `minLength`, `maxLength`, `requireUppercase`, `requireLowercase`,
     * `requireNumbers`, `requireSymbols`, `blocklistEnabled`, `historyCount`,
     * `hibpEnabled`, `complexityMode`, `minimumCharacterTypes`.
     *
     * @param array{groups?: string[]} $params optional resolution context
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function requirements(array $params = []): array
    {
        $settings = $this->_resolveSettings($params);

        return [
            'minLength' => (int)$settings->minLength,
            'maxLength' => (int)$settings->maxLength,
            'requireUppercase' => $settings->cases,
            'requireLowercase' => $settings->cases,
            'requireNumbers' => $settings->numbers,
            'requireSymbols' => $settings->symbols,
            'blocklistEnabled' => $settings->checkCommonPasswords,
            'historyCount' => (int)$settings->passwordHistoryCount,
            'hibpEnabled' => $settings->hibp,
            'complexityMode' => $settings->complexityMode,
            'minimumCharacterTypes' => (int)$settings->minimumCharacterTypes,
            'sequentialCharsCheck' => $settings->checkSequentialChars,
            'repeatedCharsCheck' => $settings->checkRepeatedChars,
            'contextualCheck' => $settings->checkContextual,
        ];
    }

    /**
     * Returns a single human-readable summary of the resolved policy, suitable
     * for rendering as a hint underneath a password input.
     *
     * @param array{groups?: string[]} $params optional resolution context
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function requirementsText(array $params = []): string
    {
        $settings = $this->_resolveSettings($params);
        $parts = [];

        $minLength = (int)$settings->minLength;
        $parts[] = Craft::t(
            'password-policy',
            'at least {n} characters',
            ['n' => $minLength],
        );

        if ($settings->cases) {
            $parts[] = Craft::t('password-policy', 'mixed case');
        }

        if ($settings->numbers) {
            $parts[] = Craft::t('password-policy', 'a number');
        }

        if ($settings->symbols) {
            $parts[] = Craft::t('password-policy', 'a symbol');
        }

        if ($settings->complexityMode === 'minimum' && $settings->minimumCharacterTypes > 0) {
            $parts[] = Craft::t(
                'password-policy',
                '{n} of 4 character types',
                ['n' => (int)$settings->minimumCharacterTypes],
            );
        }

        return Craft::t('password-policy', 'Password must contain: ') . implode(', ', $parts) . '.';
    }

    /**
     * Returns the resolved policy as a list of structured rule rows suitable
     * for rendering bespoke checklists. Each row has a `key`, a translated
     * `label`, and a `met` flag (always `null` server-side — the JS asset
     * fills it in by mapping AJAX-validate response keys to the same row keys).
     *
     * @param array{groups?: string[]} $params optional resolution context
     * @return list<array{key: string, label: string, met: ?bool}>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function requirementRules(array $params = []): array
    {
        $settings = $this->_resolveSettings($params);
        $rules = [];

        $minLength = (int)$settings->minLength;
        $rules[] = [
            'key' => 'length',
            'label' => Craft::t(
                'password-policy',
                'At least {n} characters',
                ['n' => $minLength],
            ),
            'met' => null,
        ];

        if ($settings->cases) {
            $rules[] = [
                'key' => 'cases',
                'label' => Craft::t('password-policy', 'Upper- and lower-case letters'),
                'met' => null,
            ];
        }

        if ($settings->numbers) {
            $rules[] = [
                'key' => 'numbers',
                'label' => Craft::t('password-policy', 'At least one number'),
                'met' => null,
            ];
        }

        if ($settings->symbols) {
            $rules[] = [
                'key' => 'symbols',
                'label' => Craft::t('password-policy', 'At least one symbol'),
                'met' => null,
            ];
        }

        if ($settings->complexityMode === 'minimum' && $settings->minimumCharacterTypes > 0) {
            $rules[] = [
                'key' => 'character-types',
                'label' => Craft::t(
                    'password-policy',
                    '{n} of 4 character types (uppercase, lowercase, number, symbol)',
                    ['n' => (int)$settings->minimumCharacterTypes],
                ),
                'met' => null,
            ];
        }

        if ($settings->checkCommonPasswords) {
            $rules[] = [
                'key' => 'blocklist',
                'label' => Craft::t('password-policy', 'Not a commonly used password'),
                'met' => null,
            ];
        }

        if ($settings->hibp) {
            $rules[] = [
                'key' => 'hibp',
                'label' => Craft::t('password-policy', 'Not appearing in known data breaches'),
                'met' => null,
            ];
        }

        return $rules;
    }

    // Public Methods — Tag accessors (P1.12)
    // =========================================================================

    /**
     * Returns a fluent `<input type="password">` builder.
     *
     * @param array<string, mixed> $params chainable defaults
     * @return PasswordFieldTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function passwordField(array $params = []): PasswordFieldTag
    {
        return new PasswordFieldTag($params);
    }

    /**
     * Returns a fluent requirement-list builder.
     *
     * @param array<string, mixed> $params chainable defaults
     * @return RequirementListTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function requirementList(array $params = []): RequirementListTag
    {
        return new RequirementListTag($params);
    }

    /**
     * Returns a fluent strength-meter builder.
     *
     * @param array<string, mixed> $params chainable defaults
     * @return StrengthMeterTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function strengthMeter(array $params = []): StrengthMeterTag
    {
        return new StrengthMeterTag($params);
    }

    /**
     * Returns a fluent requirements-hint builder (single human-readable summary).
     *
     * @param array<string, mixed> $params chainable defaults
     * @return RequirementsHintTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function requirementsHint(array $params = []): RequirementsHintTag
    {
        return new RequirementsHintTag($params);
    }

    /**
     * Returns a fluent composite widget (input + meter + checklist + hint).
     *
     * @param array<string, mixed> $params chainable defaults
     * @return PasswordWidgetTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function passwordWidget(array $params = []): PasswordWidgetTag
    {
        return new PasswordWidgetTag($params);
    }

    /**
     * Returns a fluent login-form builder targeting Craft's `users/login`.
     *
     * @param array<string, mixed> $params chainable defaults
     * @return LoginFormTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function loginForm(array $params = []): LoginFormTag
    {
        return new LoginFormTag($params);
    }

    /**
     * Returns a fluent password-change-form builder for a logged-in user.
     *
     * @param array<string, mixed> $params chainable defaults
     * @return PasswordChangeFormTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function passwordChangeForm(array $params = []): PasswordChangeFormTag
    {
        return new PasswordChangeFormTag($params);
    }

    /**
     * Returns a fluent password-reset-form builder for a token-based reset.
     *
     * @param array<string, mixed> $params chainable defaults
     * @return PasswordResetFormTag
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function passwordResetForm(array $params = []): PasswordResetFormTag
    {
        return new PasswordResetFormTag($params);
    }

    // Private Methods
    // =========================================================================

    /**
     * Resolves the appropriate SettingsModel for the given context.
     *
     * Lite installs always return the global settings. Pro installs use
     * PolicyResolverService for per-group resolution when the caller passes
     * group handles or when the current user has groups.
     *
     * @param array{groups?: string[]} $params resolution context
     * @return SettingsModel
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveSettings(array $params): SettingsModel
    {
        $plugin = PasswordPolicy::$plugin;
        $global = $plugin->getSettings();

        if (!$plugin->getIsPro() || !$global->enablePerGroupPolicies) {
            return $global;
        }

        // Anonymous group-preview path: caller passed handles explicitly
        if (!empty($params['groups'])) {
            $groupIds = [];

            foreach ((array)$params['groups'] as $handle) {
                $group = Craft::$app->getUserGroups()->getGroupByHandle((string)$handle);

                if ($group !== null) {
                    $groupIds[] = $group->id;
                }
            }

            if (empty($groupIds)) {
                return $global;
            }

            $policies = $plugin->getPolicies()->getPoliciesForGroupIds($groupIds);

            if (empty($policies)) {
                return $global;
            }

            // Build a fake user with these groups so we can reuse
            // PolicyResolverService's per-group merge logic without
            // duplicating the algorithm here.
            $fake = new User();
            $fake->setGroups(array_values(array_filter(array_map(
                fn(int $id) => Craft::$app->getUserGroups()->getGroupById($id),
                $groupIds,
            ))));

            return $plugin->getPolicyResolver()->resolveForUser($fake);
        }

        // Logged-in user path
        $user = $this->_getCurrentUser();

        if ($user === null) {
            return $global;
        }

        return $plugin->getPolicyResolver()->resolveForUser($user);
    }

    /**
     * Returns the currently logged-in user.
     *
     * @return User|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getCurrentUser(): ?User
    {
        /** @var User|null */
        return Craft::$app->getUser()->getIdentity();
    }

    /**
     * Returns the last password change date for a user, fetched directly
     * from the users table.
     *
     * Craft's UserQuery::beforePrepare() does not include lastPasswordChangeDate
     * in its default column selection, so User elements loaded via getIdentity()
     * always have this property as null. This method queries the column directly
     * to get the actual value.
     *
     * @param User $user
     * @return DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getLastPasswordChangeDate(User $user): ?DateTime
    {
        $date = (new Query())
            ->select(['lastPasswordChangeDate'])
            ->from(Table::USERS)
            ->where(['id' => $user->id])
            ->scalar();

        if ($date === false || $date === null) {
            return null;
        }

        return DateTimeHelper::toDateTime($date) ?: null;
    }

    /**
     * Calculates the password expiry date for a user based on settings.
     *
     * @param User $user
     * @return DateTime|null null if no expiration configured
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getExpiryDate(User $user): ?DateTime
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $lastChange = $this->_getLastPasswordChangeDate($user);

        if ($lastChange === null) {
            return null;
        }

        $expiry = clone $lastChange;

        $interval = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => 'P' . ($settings->expiryAmount * 7) . 'D',
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => "P{$settings->expiryAmount}D",
        };

        $expiry->add(new \DateInterval($interval));

        return $expiry;
    }
}
