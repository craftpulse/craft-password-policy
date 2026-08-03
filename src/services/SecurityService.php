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
use craft\base\Component;
use craft\elements\User as UserElement;
use yii\base\Exception;

/**
 * Class SecurityService
 *
 * Owns the plugin's cross-cutting security primitives — the ones that belong to
 * no single feature:
 *
 *  - {@see self::canManageUserCredentials()}: the peer-admin gate shared by every
 *    admin-on-user credential write.
 *  - {@see self::getNonce()}: CSP-nonce generation for the plugin's own scripts.
 *    The plugin only nonce-tags scripts it registers itself (the CP strength
 *    indicator); it does NOT emit a site-wide Content-Security-Policy header.
 *    Operators own their CSP, and the plugin's job is to be nonce-compatible with
 *    a strict policy, supplying the nonce to asset registration when `cspNonce`
 *    is enabled.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.1.0
 */
class SecurityService extends Component
{
    // Private Properties
    // =========================================================================

    /**
     * @var string|null the nonce
     */
    private ?string $_nonce = null;

    // Public Methods
    // =========================================================================

    /**
     * Returns whether `$actor` is allowed to perform an admin-on-user credential
     * write on `$target` — the peer-admin gate shared by every surface that
     * replaces or invalidates another account's password.
     *
     * Four surfaces consume it: the Password Security pane's Actions flag, the
     * force-reset POST handler on `UserSecurityController`, the
     * `ForcePasswordReset` bulk element action, and the direct
     * password-set handler on `UserPasswordController`.
     *
     * Two rules, in order:
     *
     *  1. No identified actor, no write. Callers that reach a write path without
     *     a session are rejected outright.
     *  2. A non-admin may never aim a credential write at an admin. Both
     *     capabilities behind this gate are escalation primitives — setting an
     *     administrator's password outright is account takeover, and locking one
     *     out of their own account is a denial primitive — while both
     *     {@see \craftpulse\passwordpolicy\PasswordPolicy::PERMISSION_USER_FORCE_RESET}
     *     and `pp:change-user-passwords` are grantable to non-admin groups by
     *     design. The permission alone must therefore not carry either across a
     *     privilege boundary. Admin-on-admin stays allowed: co-administrators are
     *     peers and Craft already treats them as mutually trusted, which is
     *     exactly the rule core applies to its own admin-on-admin writes (see
     *     `UsersController::actionUnlockUser()`).
     *
     * Deliberately a single predicate rather than one check per surface:
     * duplicated authorization drifts, and the copy that drifts is the one nobody
     * tests. It lives here rather than on `RetentionService` because it now gates
     * a password-setting controller as well as the retention-adjacent force-reset
     * paths, and retention is not the shared concern between them.
     *
     * @param UserElement $target the account that would be written to
     * @param UserElement|null $actor the acting CP session's identity
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canManageUserCredentials(UserElement $target, ?UserElement $actor): bool
    {
        if ($actor === null) {
            return false;
        }

        return !$target->admin || $actor->admin;
    }

    /**
     * Generates and returns the CSP nonce for this request.
     *
     * @return string
     *
     * @throws Exception
     *
     * @author CraftPulse
     */
    public function getNonce(): string
    {
        if ($this->_nonce === null) {
            $this->_nonce = Craft::$app->getSecurity()->generateRandomString(32);
        }

        return $this->_nonce;
    }
}
