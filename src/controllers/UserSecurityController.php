<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\DateTimeHelper;
use craft\web\Controller;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class UserSecurityController
 *
 * Renders the standalone "Password Security" CP page for a single user
 * (`password-policy/users/<userId>/security`). The page is the read-only
 * surface that the half-built `_users/password-security.twig` template
 * was designed for: status snapshot, resolved policy summary, and the
 * "Force Password Reset" button which posts to the existing
 * `password-policy/retention/force-reset` endpoint.
 *
 * The page is reachable two ways:
 *  1. Directly via the CP URL rule registered in
 *     {@see PasswordPolicy::_registerCpUrlRules()}.
 *  2. Via the "Password Security" link appended to the User edit
 *     screen sidebar by {@see PasswordPolicy::_registerUserEditTab()}
 *     using {@see \craft\base\Element::EVENT_DEFINE_SIDEBAR_HTML}.
 *
 * Permission gate: the caller needs either `pp:force-reset-passwords`
 * (Pro-tier action exposed on this page) or `pp:change-user-passwords`
 * (D3 admin-direct password change permission). Either grants visibility
 * — both permissions concern the same admin-on-user surface, and
 * splitting them at this level would surface a meaningless "you can see
 * the page but every action is greyed out" state.
 *
 * Read-only mode: the page still renders when
 * `allowAdminChanges = false` — read-only data (status, policy summary)
 * is fine to show. The template itself is responsible for the
 * `readOnlyNotice()` banner + disabling form controls.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserSecurityController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<int|string>|bool|int CP-only — every action requires
     *     an authenticated admin session.
     */
    protected array|bool|int $allowAnonymous = false;

    // Public Methods
    // =========================================================================

    /**
     * Pre-action gates shared by every endpoint on this controller:
     * CP request + permission. The permission gate accepts either of
     * the two related admin-on-user permissions — the template offers
     * affordances tied to both, and forcing callers to hold both would
     * not match how operators get assigned permissions in practice.
     *
     * @param \yii\base\Action $action
     * @return bool
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();

        if (!self::callerHasViewPermission()) {
            throw new ForbiddenHttpException(
                Craft::t('password-policy', 'User is not permitted to view the Password Security tab.')
            );
        }

        return true;
    }

    /**
     * Returns whether the currently-identified CP user is permitted to
     * see the Password Security tab. Either of the two related
     * admin-on-user permissions grants visibility:
     *
     *  - `pp:force-reset-passwords` — flips `passwordResetRequired`
     *    via the existing retention endpoint.
     *  - `pp:change-user-passwords` — D3's direct admin password change
     *    + send-reset-email permission.
     *
     * Exposed as a static helper so the registration listener can gate
     * the sidebar link with the same predicate the controller's
     * `beforeAction()` enforces — single source of truth.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function callerHasViewPermission(): bool
    {
        $user = Craft::$app->getUser()->getIdentity();

        if ($user === null) {
            return false;
        }

        return $user->can('pp:force-reset-passwords')
            || $user->can('pp:change-user-passwords');
    }

    /**
     * Renders the Password Security page for a single user.
     *
     * Loads the user, hydrates `lastPasswordChangeDate` directly from
     * the users table (memory gap #9 — UserQuery doesn't select it),
     * resolves the effective policy via `PolicyResolverService`, and
     * derives the status flags the template renders against
     * (`isExpired`, `neverChanged`, `policySource`).
     *
     * @param int $userId the user's element id
     * @return Response
     *
     * @throws NotFoundHttpException when no user exists with the given id
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(int $userId): Response
    {
        $user = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null) {
            throw new NotFoundHttpException(
                Craft::t('password-policy', 'User not found.')
            );
        }

        $plugin = PasswordPolicy::$plugin;

        // Memory gap #9 — `craft\elements\db\UserQuery::beforePrepare()`
        // does NOT addSelect `lastPasswordChangeDate`, so the in-memory
        // `$user->lastPasswordChangeDate` is always null regardless of
        // the column value. Pull the column directly and pin it on the
        // element so the template's `user.lastPasswordChangeDate|date`
        // resolves against real data.
        $lastChangeRaw = (new Query())
            ->select(['lastPasswordChangeDate'])
            ->from(Table::USERS)
            ->where(['id' => $user->id])
            ->scalar();

        $lastChange = $lastChangeRaw !== false
            ? DateTimeHelper::toDateTime($lastChangeRaw) ?: null
            : null;

        $user->lastPasswordChangeDate = $lastChange;

        $policy = $plugin->getPolicyResolver()->resolveForUser($user);
        $policySource = $this->_describePolicySource($user, $policy === $plugin->getSettings());

        $expiryThreshold = $this->_getExpiryThreshold();
        $isExpired = $expiryThreshold !== null
            && $lastChange !== null
            && $lastChange < $expiryThreshold;

        return $this->renderTemplate('password-policy/_users/password-security', [
            'user' => $user,
            'policy' => $policy,
            'policySource' => $policySource,
            'isExpired' => $isExpired,
            'neverChanged' => $lastChange === null,
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the expiry threshold derived from settings, or null when
     * no expiry is configured. Mirrors the parsing logic in
     * `UserIndexService::_getExpiryThreshold()` — kept inline rather
     * than exposed publicly so the service stays an internal helper.
     *
     * @return \DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getExpiryThreshold(): ?\DateTime
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $spec = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };

        if ($spec === null) {
            return null;
        }

        try {
            return (new \DateTime('now'))->sub(new \DateInterval($spec));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Returns a human-readable description of why the resolved policy
     * applies to the given user. Three cases:
     *
     *  - Global — Pro disabled, per-group disabled, or no matching
     *    policies returned by the resolver.
     *  - Single matching named policy — the policy's name.
     *  - Multiple matching named policies — comma-joined names with a
     *    "merged from" prefix to signal the most-restrictive merge.
     *
     * Pure presentation helper. The resolver itself doesn't return the
     * source rationale because the merged settings model has no slot
     * for it — the controller derives it from the same group-policy
     * lookup the resolver uses internally.
     *
     * @param \craft\elements\User $user
     * @param bool $resolvedToGlobal whether the resolver returned the
     *     plugin's global settings instance unchanged
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _describePolicySource(\craft\elements\User $user, bool $resolvedToGlobal): string
    {
        if ($resolvedToGlobal) {
            return Craft::t('password-policy', 'Global');
        }

        $plugin = PasswordPolicy::$plugin;
        $groups = $user->getGroups();

        if (empty($groups)) {
            return Craft::t('password-policy', 'Global');
        }

        $groupIds = array_map(static fn($g) => $g->id, $groups);
        $policies = $plugin->getPolicies()->getPoliciesForGroupIds($groupIds);

        if (empty($policies)) {
            return Craft::t('password-policy', 'Global');
        }

        if (count($policies) === 1) {
            return $policies[0]->name;
        }

        return Craft::t('password-policy', 'Merged from {names}', [
            'names' => implode(', ', array_map(static fn($p) => $p->name, $policies)),
        ]);
    }
}
