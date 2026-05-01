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

use Craft;
use craft\elements\User;
use craft\errors\ElementNotFoundException;
use craftpulse\passwordpolicy\events\UserRegisteredEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use InvalidArgumentException;
use RuntimeException;
use Throwable;
use yii\base\Component;
use yii\base\Exception;
use yii\base\InvalidConfigException;

/**
 * Class RegistrationService
 *
 * Programmatic registration helper that wraps the create-user-and-assign-groups
 * flow used by consumer registration forms. Resolves group handles to IDs at
 * call time (more dev-friendly than requiring the consumer to know IDs),
 * pre-validates the proposed password against the resolved policy (Lite uses
 * global; Pro resolves per-group via PolicyResolverService against the assigned
 * groups), persists the user, assigns groups, optionally sends an activation
 * email, and fires `UserRegisteredEvent` on success.
 *
 * Validation failures throw an `InvalidArgumentException` exposing per-field
 * errors so consumer controllers can surface them naturally.
 *
 * @event UserRegisteredEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class RegistrationService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Fired after a user has been successfully registered through this service.
     *
     * @event UserRegisteredEvent
     *
     * @since 5.2.0
     */
    public const EVENT_USER_REGISTERED = 'userRegistered';

    // Public Methods
    // =========================================================================

    /**
     * Registers a new Craft user, validating the proposed password against the
     * resolved password policy for the assigned groups.
     *
     * Accepted params:
     * - `email` (string, required)
     * - `password` (string, required) — plaintext, validated then handed to Craft for hashing
     * - `username` (string, optional) — defaults to email
     * - `groups` (string[]) — array of user group **handles**; resolved to IDs at call time
     * - `fields` (array) — custom field values keyed by handle, passed to `setFieldValues()`
     * - `sendActivationEmail` (bool, optional) — when null, follows Craft's
     *   `users.requireEmailVerification` project-config flag
     *
     * @param array $params the registration payload (see method body)
     * @return User the persisted user
     *
     * @throws ElementNotFoundException
     * @throws Exception
     * @throws InvalidArgumentException when required params are missing, group handles are unknown, or validation fails
     * @throws InvalidConfigException
     * @throws RuntimeException when the user save itself fails for non-validation reasons
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function register(array $params): User
    {
        $email = trim((string)($params['email'] ?? ''));
        $password = (string)($params['password'] ?? '');

        if ($email === '') {
            throw new InvalidArgumentException('The "email" parameter is required.');
        }

        if ($password === '') {
            throw new InvalidArgumentException('The "password" parameter is required.');
        }

        $username = trim((string)($params['username'] ?? '')) ?: $email;
        $groupHandles = (array)($params['groups'] ?? []);
        $fieldValues = (array)($params['fields'] ?? []);
        $sendActivationEmail = $params['sendActivationEmail'] ?? null;

        // Resolve group handles to IDs up front — fail loud on unknown handles
        // so the caller learns about typos before any side effects run.
        $groupIds = $this->_resolveGroupHandles($groupHandles);

        // Build the user element. We assign groups *after* save (Craft's
        // pattern), but we set them on the in-memory user before validation
        // so the resolver sees the intended group context for per-group
        // policy resolution.
        $user = new User();
        $user->email = $email;
        $user->username = $username;
        $user->newPassword = $password;
        $user->setGroups($this->_loadGroupModels($groupIds));

        if (!empty($fieldValues)) {
            $user->setFieldValues($fieldValues);
        }

        // Validate first — this runs UserRules with the resolved policy
        // (per-group on Pro, global on Lite — see UserRules::defineRules()).
        if (!$user->validate()) {
            $errors = $user->getErrors();
            throw new InvalidArgumentException(
                $this->_flattenErrors($errors),
                code: 0,
            );
        }

        // Persist the user (validation already ran above, skip duplicate run)
        if (!Craft::$app->getElements()->saveElement($user, false)) {
            throw new RuntimeException(
                'Failed to save user element: ' . $this->_flattenErrors($user->getErrors()),
            );
        }

        // Assign groups (Craft's idiomatic post-save assignment path)
        if (!empty($groupIds)) {
            Craft::$app->getUsers()->assignUserToGroups($user->id, $groupIds);
        }

        // Activation email — defer to Craft's `users.requireEmailVerification`
        // project-config flag when the caller didn't explicitly opt in/out.
        if ($this->_shouldSendActivationEmail($user, $sendActivationEmail)) {
            try {
                Craft::$app->getUsers()->sendActivationEmail($user);
            } catch (Throwable $e) {
                Craft::warning(
                    'Registration succeeded but activation email send failed: ' . $e->getMessage(),
                    'password-policy',
                );
            }
        }

        // Fire developer event
        if ($this->hasEventHandlers(self::EVENT_USER_REGISTERED)) {
            $this->trigger(self::EVENT_USER_REGISTERED, new UserRegisteredEvent([
                'user' => $user,
                'groups' => $groupHandles,
                'viaService' => true,
            ]));
        }

        PasswordPolicy::$plugin->log(
            'User {userId} registered via RegistrationService (groups: {groups})',
            [
                'userId' => $user->id,
                'groups' => implode(',', $groupHandles) ?: '(none)',
            ],
        );

        return $user;
    }

    // Private Methods
    // =========================================================================

    /**
     * Flattens a `[attribute => [messages...]]` error array into a single
     * human-readable string for exception messages.
     *
     * @param array<string, string[]> $errors the validation errors
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _flattenErrors(array $errors): string
    {
        $lines = [];

        foreach ($errors as $attribute => $messages) {
            foreach ((array)$messages as $message) {
                $lines[] = "{$attribute}: {$message}";
            }
        }

        return implode('; ', $lines);
    }

    /**
     * Returns the UserGroup model instances for the given group IDs, in the
     * same order as the input array.
     *
     * @param int[] $groupIds the group IDs to load
     * @return \craft\models\UserGroup[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _loadGroupModels(array $groupIds): array
    {
        $groups = [];

        foreach ($groupIds as $id) {
            $group = Craft::$app->getUserGroups()->getGroupById($id);

            if ($group !== null) {
                $groups[] = $group;
            }
        }

        return $groups;
    }

    /**
     * Resolves an array of group handles to a deduplicated array of group IDs.
     * Throws `InvalidArgumentException` on the first unknown handle so the
     * caller hears about typos immediately.
     *
     * @param string[] $handles the group handles
     * @return int[] the resolved IDs
     *
     * @throws InvalidArgumentException when a handle does not match an existing group
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveGroupHandles(array $handles): array
    {
        $ids = [];

        foreach ($handles as $handle) {
            $handle = (string)$handle;
            $group = Craft::$app->getUserGroups()->getGroupByHandle($handle);

            if ($group === null) {
                throw new InvalidArgumentException("Unknown user group handle: \"{$handle}\".");
            }

            $ids[$group->id] = true;
        }

        return array_keys($ids);
    }

    /**
     * Decides whether to send the activation email for the given user.
     *
     * - Explicit `true` / `false` from the caller wins.
     * - Otherwise honors Craft's `users.requireEmailVerification` project-config
     *   flag (defaults to true on Pro+ Craft installs).
     *
     * @param User $user the user that was just persisted
     * @param bool|null $explicit the caller's explicit preference, or null to defer to Craft
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _shouldSendActivationEmail(User $user, ?bool $explicit): bool
    {
        if ($explicit !== null) {
            return $explicit;
        }

        // If the user is already active (admin-created), no activation email
        if ($user->getStatus() === User::STATUS_ACTIVE) {
            return false;
        }

        return (bool)Craft::$app->getProjectConfig()->get('users.requireEmailVerification');
    }
}
