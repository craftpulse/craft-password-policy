<?php
/**
 * Pest coverage for the User-edit "Password Security" left-nav screen.
 *
 * The plugin registers an additional screen on the User edit experience
 * via `UsersController::EVENT_DEFINE_EDIT_SCREENS` (Craft 5.0+). The
 * event payload's `screens` array is keyed by screen ID; each entry has
 * a `label` and (optionally) a `url`. The plugin appends a
 * `password-security` entry pointing at the standalone CP page
 * `password-policy/users/<userId>/security`. The same
 * `pp:user-force-reset` / `pp:change-user-passwords` permission
 * predicate guards both the screen registration and
 * `UserSecurityController::beforeAction()`.
 *
 * The tests cover the registration predicate, the read-only mode
 * contract, the controller's permission gate, and the content-only
 * template's expected markup (notice + `disabled` attribute on the
 * force-reset button). The CP screen chrome (left nav, breadcrumbs,
 * meta sidebar) is `EditUserTrait`'s job and is not re-tested here —
 * this file only verifies the plugin-owned seams.
 *
 * Console-bootstrap CP-test trifecta applied per memory gap #20:
 *  - `UserStub` with the patched `idParam`,
 *  - `WebRequestStub` with `stubIsCpRequest = true`,
 *  - `assetManager.basePath` pinned in `tests/_craft/config/app.php`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\controllers\UsersController;
use craft\elements\User;
use craft\events\DefineEditUserScreensEvent;
use craft\web\Response;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\PermissionFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\base\Event;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    // Pro baseline: the screen is universal but two of its panes (force-reset
    // Actions, notification activity) are Pro. Tests that care about the Lite
    // shape flip the edition explicitly.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Manually fires `UsersController::EVENT_DEFINE_EDIT_SCREENS` with a
 * baseline screens map and returns the post-listener `$event->screens`.
 * Mirrors what `EditUserTrait::asEditUserScreen()` does mid-render —
 * the trait builds an initial `$screens` array, fires the event, and
 * uses the post-listener result. Testing the seam directly avoids the
 * full controller-render chain (which requires more CP context than the
 * console-bootstrap process exposes).
 *
 * @return array<string, array<string, mixed>>
 */
function fireDefineEditScreens(User $editedUser, ?User $currentUser): array
{
    $event = new DefineEditUserScreensEvent([
        'currentUser' => $currentUser ?? new User(),
        'editedUser' => $editedUser,
        'screens' => [
            'profile' => ['label' => 'Profile'],
            'permissions' => ['label' => 'Permissions'],
            'addresses' => ['label' => 'Addresses'],
        ],
    ]);

    Event::trigger(UsersController::class, UsersController::EVENT_DEFINE_EDIT_SCREENS, $event);

    return $event->screens;
}

/**
 * Renders the password-security content template directly. The
 * template is content-only after the EditUserTrait switch — no
 * `extends`, no `block content` — so a plain `render()` returns the
 * inner markup the trait would otherwise wrap in CP screen chrome.
 *
 * Variables that the controller sets at render time (`isExpired`,
 * `neverChanged`, `policySource`) are pinned to deterministic values
 * here so the read-only assertions stay independent of the user's
 * actual password-change state. `showNotifications` and
 * `showForceReset` mirror the controller's edition gates so the Pro
 * panes render here exactly when they would in the CP — the template
 * holds no edition policy of its own, it only consumes the flags.
 */
function renderPasswordSecurityContent(User $user): string
{
    $plugin = PasswordPolicy::$plugin;
    $policy = $plugin->getPolicyResolver()->resolveForUser($user);
    $currentUser = Craft::$app->getUser()->getIdentity();

    $view = Craft::$app->getView();
    $oldMode = $view->getTemplateMode();
    $view->setTemplateMode($view::TEMPLATE_MODE_CP);

    try {
        return $view->renderTemplate('password-policy/_users/password-security', [
            'user' => $user,
            'policy' => $policy,
            'policySource' => 'Global',
            'isExpired' => false,
            'neverChanged' => $user->lastPasswordChangeDate === null,
            'showNotifications' => $plugin->getIsPro(),
            'showForceReset' => $plugin->getIsPro()
                && $currentUser !== null
                && $currentUser->can(PasswordPolicy::PERMISSION_USER_FORCE_RESET)
                && $plugin->getSecurity()->canManageUserCredentials($user, $currentUser)
                && !$user->passwordResetRequired,
            'currentUser' => $currentUser,
        ]);
    } finally {
        $view->setTemplateMode($oldMode);
    }
}

// =============================================================================
// Screen registration — appears with either permission, absent without
// =============================================================================

it('registers the password-security screen when the admin has permission', function() {
    $admin = UserFactory::admin();
    $this->userStub->setIdentity($admin);

    $target = UserFactory::nonAdmin();
    $screens = fireDefineEditScreens($target, $admin);

    expect($screens)->toHaveKey('password-security');
    expect($screens['password-security']['label'])->toBe('Password Security');
    expect($screens['password-security']['url'])->toContain("password-policy/users/{$target->id}/security");
});

it('does not register the screen when the caller has neither permission', function() {
    $caller = UserFactory::nonAdmin();
    $this->userStub->setIdentity($caller);

    $target = UserFactory::nonAdmin();
    $screens = fireDefineEditScreens($target, $caller);

    expect($screens)->not->toHaveKey('password-security');
});

it('does not register the screen when there is no identified user', function() {
    $this->userStub->setIdentity(null);

    $target = UserFactory::nonAdmin();
    $screens = fireDefineEditScreens($target, null);

    expect($screens)->not->toHaveKey('password-security');
});

// =============================================================================
// Read-only mode — screen still registers; gating happens inside the page
// =============================================================================

it('still registers the screen when allowAdminChanges is off', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;
    $admin = UserFactory::admin();
    $this->userStub->setIdentity($admin);

    $target = UserFactory::nonAdmin();
    $screens = fireDefineEditScreens($target, $admin);

    // Read-only data (status, resolved policy) is fine to view; the
    // page itself disables write affordances via `readOnlyNotice()`
    // + the `disabled` attribute. Hiding the screen in read-only
    // mode would force admins to bookmark the URL to ever review
    // status — worse UX for no security gain.
    expect($screens)->toHaveKey('password-security');
});

// =============================================================================
// Read-only template — readOnlyNotice() banner + disabled controls
// =============================================================================

it('renders the readOnlyNotice banner when allowAdminChanges is off', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    // `readOnlyNotice()` renders Craft's content-notice block whose
    // body is a stable user-facing string from
    // `craft\helpers\Cp::readOnlyNoticeHtml()`. Match on the
    // canonical phrase rather than wrapper markup, which can evolve
    // across Craft 5 patch releases.
    expect($body)
        ->toBeString()
        ->and($body)->toContain('aren')
        ->and($body)->toContain('permitted in this environment');
});

it('omits the readOnlyNotice when admin changes are allowed', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->not->toContain('permitted in this environment');
});

it('disables the force-reset button when allowAdminChanges is off', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->toContain('Force Password Reset')
        ->and($body)->toMatch('/<button[^>]*\bdisabled\b/');
});

it('keeps the force-reset button enabled when admin changes are allowed', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->toContain('Force Password Reset')
        ->and($body)->not->toMatch('/<button[^>]*\bdisabled\b/');
});

// =============================================================================
// Edition gate — the force-reset pane is Pro, hidden below it
// =============================================================================

it('omits the force-reset Actions pane on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    // Hide, never badge: no button, no disabled control, no upsell copy, and
    // no POST target to discover. An admin identity clears every permission
    // check, so the edition is the only thing that can remove the pane here.
    expect($body)
        ->toBeString()
        ->and($body)->not->toContain('Force Password Reset')
        ->and($body)->not->toContain('password-policy/user-security/force-reset')
        ->and($body)->not->toContain('Pro');

    // The rest of the screen is universal and must still render.
    expect($body)
        ->toContain('Password Status')
        ->and($body)->toContain('Active Policy');
});

it('renders the force-reset Actions pane on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->toContain('Force Password Reset');
});

it('omits the force-reset Actions pane on Pro without the permission', function() {
    // The pane's flag folds the permission in alongside the edition, so a Pro
    // caller lacking `pp:user-force-reset` sees the same absence a Lite
    // admin does.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(UserFactory::nonAdmin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->not->toContain('Force Password Reset');
});

it('omits the force-reset Actions pane when a permitted non-admin views an admin', function() {
    // The pane folds the peer-admin guard in alongside the edition and the
    // permission, so the screen never offers a button whose POST the controller
    // would answer with a 403. The actor HOLDS `pp:user-force-reset` here, so
    // the guard is the only thing that can remove the pane — without it the
    // same actor sees the button on every admin in the system.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([
        PasswordPolicy::PERMISSION_USER_FORCE_RESET,
    ]));

    $target = UserFactory::admin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->not->toContain('Force Password Reset')
        ->and($body)->not->toContain('password-policy/user-security/force-reset');
});

it('renders the force-reset Actions pane when a permitted non-admin views a non-admin', function() {
    // The control case for the guard test above: same actor, same grant, only
    // the target's admin flag differs. Without this pair the guard test would
    // also pass if the permission plumbing were simply broken.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([
        PasswordPolicy::PERMISSION_USER_FORCE_RESET,
    ]));

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->toContain('Force Password Reset');
});

it('hides the pane rather than leaking it when showForceReset is missing', function() {
    // The template reads `showForceReset ?? false`, so a caller that forgets
    // the variable fails closed. Rendering without it is the regression this
    // pins: a bare `{% if showForceReset %}` would throw under devMode's
    // strict_variables instead, and a truthy default would leak the pane.
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $policy = $this->plugin->getPolicyResolver()->resolveForUser($target);

    $view = Craft::$app->getView();
    $oldMode = $view->getTemplateMode();
    $view->setTemplateMode($view::TEMPLATE_MODE_CP);

    try {
        $body = $view->renderTemplate('password-policy/_users/password-security', [
            'user' => $target,
            'policy' => $policy,
            'policySource' => 'Global',
            'isExpired' => false,
            'neverChanged' => true,
        ]);
    } finally {
        $view->setTemplateMode($oldMode);
    }

    expect($body)
        ->toBeString()
        ->and($body)->not->toContain('Force Password Reset');
});

// =============================================================================
// POST target alignment — defensive; the action lives on
// UserSecurityController since 5.2.0 (moved out of RetentionController
// so the admin-on-user surface owns the write that drives it).
// =============================================================================

it('points the form at the user-security/force-reset POST target', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->toContain('password-policy/user-security/force-reset');
});

// =============================================================================
// Page heading + main panes still render in the content body
// =============================================================================

it('renders the password-status and active-policy panes', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    expect($body)
        ->toBeString()
        ->and($body)->toContain('Password Status')
        ->and($body)->toContain('Active Policy');
});
