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
use craft\controllers\EditUserTrait;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\DateTimeHelper;
use craft\web\Controller;
use craft\web\CpScreenResponseBehavior;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class UserSecurityController
 *
 * Renders the "Password Security" screen on the User edit experience
 * (`password-policy/users/<userId>/security`). Status snapshot,
 * resolved policy summary, and the "Force Password Reset" button —
 * the force-reset POST target lives here too (since 5.2.0 — moved
 * from `RetentionController::actionForceReset()` so the admin-on-user
 * surface owns the action that drives it).
 *
 * Uses Craft's {@see EditUserTrait} so the response shares the user-
 * edit screen chrome — left-nav (Profile / Permissions / Addresses /
 * Password Security), title, breadcrumbs, meta sidebar — with the
 * native Craft user-edit screens. The Password Security entry is
 * registered into the trait's `$screens` map by the plugin's listener
 * on {@see \craft\controllers\UsersController::EVENT_DEFINE_EDIT_SCREENS}
 * (see {@see PasswordPolicy::_registerUserEditScreen()}). Same screen
 * key used here (`password-security`) and there.
 *
 * Permission gate: the caller needs either `pp:force-reset-passwords`
 * (Pro-tier action exposed on this page) or `pp:change-user-passwords`
 * (D3 admin-direct password change permission). Either grants
 * visibility — both permissions concern the same admin-on-user
 * surface, and splitting them at this level would surface a
 * meaningless "you can see the page but every action is greyed out"
 * state.
 *
 * Read-only mode: the page still renders when
 * `allowAdminChanges = false` — read-only data (status, policy
 * summary) is fine to show. The template itself is responsible for
 * the `readOnlyNotice()` banner + disabling form controls.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserSecurityController extends Controller
{
    use EditUserTrait;

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
     * Renders the Password Security screen for a single user inside
     * the User edit screen chrome (Profile / Permissions / Addresses
     * / Password Security left nav, title, breadcrumbs, meta
     * sidebar).
     *
     * Loads the user via the trait's {@see EditUserTrait::editedUser()},
     * hydrates `lastPasswordChangeDate` directly from the users table
     * (memory gap #9 — UserQuery doesn't select it), resolves the
     * effective policy via `PolicyResolverService`, and derives the
     * status flags the template renders against (`isExpired`,
     * `neverChanged`, `policySource`). Hands content to the response
     * via `contentTemplate()` so the trait owns the surrounding
     * chrome.
     *
     * @param int|null $userId the user's element id (null routes
     *     through the trait to the current user — defensive; the URL
     *     rule always includes a `userId` capture)
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(?int $userId = null): Response
    {
        $user = $this->editedUser($userId);
        $plugin = PasswordPolicy::$plugin;

        // `craft\elements\db\UserQuery` doesn't `addSelect()` either
        // `lastPasswordChangeDate` (memory gap #9) or
        // `passwordResetRequired`, so the in-memory properties default
        // (`null` and `false`). Pull both directly and pin them on the
        // element so the template's `user.lastPasswordChangeDate|date`
        // and `user.passwordResetRequired` reads resolve against real
        // data — without this the "reset requested" banner never
        // surfaces and the Force Password Reset button always renders.
        $row = (new Query())
            ->select(['lastPasswordChangeDate', 'passwordResetRequired'])
            ->from(Table::USERS)
            ->where(['id' => $user->id])
            ->one();

        $lastChange = ($row !== null && $row['lastPasswordChangeDate'] !== null)
            ? DateTimeHelper::toDateTime($row['lastPasswordChangeDate']) ?: null
            : null;

        $user->lastPasswordChangeDate = $lastChange;
        $user->passwordResetRequired = $row !== null && (bool)$row['passwordResetRequired'];

        $policy = $plugin->getPolicyResolver()->resolveForUser($user);
        $policySource = $this->_describePolicySource($user, $policy === $plugin->getSettings());

        $expiryThreshold = $this->_getExpiryThreshold();
        $isExpired = $expiryThreshold !== null
            && $lastChange !== null
            && $lastChange < $expiryThreshold;

        $notifications = $plugin->getIsPro()
            ? $plugin->getNotificationActivity()->recentForUser($user->id)
            : [];

        /** @var Response|CpScreenResponseBehavior $response */
        $response = $this->asEditUserScreen($user, 'password-security');

        $response->contentTemplate('password-policy/_users/password-security', [
            'user' => $user,
            'policy' => $policy,
            'policySource' => $policySource,
            'isExpired' => $isExpired,
            'neverChanged' => $lastChange === null,
            'notifications' => $notifications,
        ]);

        return $response;
    }

    /**
     * Forces a password reset for a single user — the action target of
     * the "Force Password Reset" button on the user edit tab template
     * at `_users/password-security.twig`. Admin users are silently
     * skipped server-side by
     * `RetentionService::requirePasswordReset()`.
     *
     * Moved from `RetentionController::actionForceReset()` in 5.2.0
     * (pre-tag fix-pack) so the admin-on-user surface owns the action
     * that drives it — retention is a settings/utility concern; this
     * is a user-management write. URL changes from
     * `password-policy/retention/force-reset` to
     * `password-policy/user-security/force-reset`.
     *
     * Self-gated: enforces `requirePostRequest()` +
     * `requirePermission('pp:force-reset-passwords')` independent of
     * the controller-wide `beforeAction()` (which only checks the
     * union-of-permissions for tab visibility).
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionForceReset(): ?Response
    {
        $this->requirePostRequest();
        $this->requirePermission('pp:force-reset-passwords');

        $plugin = PasswordPolicy::$plugin;

        if (!$plugin->getSettings()->retentionUtilities) {
            return $this->_forceResetFailure('Password retention features are disabled.');
        }

        $userId = (int)Craft::$app->getRequest()->getRequiredBodyParam('userId');
        $user = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null) {
            throw new NotFoundHttpException('User not found.');
        }

        $plugin->retention->requirePasswordReset($user);

        return $this->_forceResetSuccess('Password reset has been requested for this user.');
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

    /**
     * Returns a success response for `actionForceReset()`. JSON for
     * AJAX callers; redirect for form submits. Drives the plugin's
     * log channel + a flash so the admin sees the outcome on the
     * user edit screen.
     *
     * @param string $message
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _forceResetSuccess(string $message): ?Response
    {
        PasswordPolicy::$plugin->log($message . ' [via password-security tab by "{username}"]');
        $this->setSuccessFlash(Craft::t('password-policy', $message));

        return $this->_forceResetResponse($message);
    }

    /**
     * Returns a failure response for `actionForceReset()`. Mirrors
     * the success path's shape so AJAX callers get a JSON
     * `{success: false}` and form submits get a flash + null
     * (caller falls back to render the same screen).
     *
     * @param string $message
     * @return Response|null
     *
     * @throws BadRequestHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _forceResetFailure(string $message): ?Response
    {
        $this->setFailFlash(Craft::t('password-policy', $message));

        return $this->_forceResetResponse($message, false);
    }

    /**
     * Returns a JSON or redirect response — shared by
     * `_forceResetSuccess()` and `_forceResetFailure()`. Matches the
     * shape `RetentionController::_getResponse()` used before the
     * action moved here.
     *
     * @param string $message
     * @param bool $success
     * @return Response|null
     *
     * @throws BadRequestHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _forceResetResponse(string $message, bool $success = true): ?Response
    {
        if (Craft::$app->getRequest()->getAcceptsJson()) {
            return $this->asJson([
                'success' => $success,
                'message' => Craft::t('password-policy', $message),
            ]);
        }

        if (!$success) {
            return null;
        }

        return $this->redirectToPostedUrl();
    }
}
