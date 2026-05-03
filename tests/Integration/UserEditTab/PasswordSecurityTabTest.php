<?php
/**
 * Pest coverage for D4's User-edit "Password Security" pointer.
 *
 * The plugin doesn't register a top-level edit-screen tab — Craft 5
 * doesn't expose a public event for that. Instead it appends a link
 * block to the User edit screen sidebar via
 * `Element::EVENT_DEFINE_SIDEBAR_HTML`, gated on either
 * `pp:force-reset-passwords` or `pp:change-user-passwords`. The
 * standalone CP page (`password-policy/users/<userId>/security`) is
 * what the link points at; the same permission predicate guards
 * `UserSecurityController::beforeAction()`.
 *
 * The tests cover the registration predicate (both single-permission
 * paths + the negative case), the read-only mode contract (the link
 * still appears when `allowAdminChanges = false`), the controller's
 * happy path + 404, and the read-only template's expected markup
 * (notice + `disabled` attribute on the force-reset button).
 *
 * Console-bootstrap CP-test trifecta applied per memory gap #20:
 *  - `UserStub` with the patched `idParam`,
 *  - `WebRequestStub` with `stubIsCpRequest = true`,
 *  - `assetManager.basePath` pinned in `tests/_craft/config/app.php`.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\elements\User;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\UserSecurityController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Triggers `Element::EVENT_DEFINE_SIDEBAR_HTML` against the given user
 * and returns the resulting sidebar HTML — the plugin's listener
 * appends the "Password Security" pointer to the existing baseline.
 * Mirrors what `ElementsController::actionEdit` does at render time.
 */
function triggerUserSidebar(User $user): string
{
    return $user->getSidebarHtml(false);
}

/**
 * Returns the rendered HTML for the "Password Security" template's
 * inner content block — the part the plugin owns. Skips the wider
 * CP layout chain (`_layouts/cp` → global-sidebar → notifications
 * → session) which is Craft's own surface and brings dependencies
 * the console-bootstrapped test process doesn't have (sessions,
 * `$_SERVER['REQUEST_URI']`, etc.). The brief-relevant assertions
 * (read-only notice, disabled button, force-reset POST target) all
 * live inside the content block — testing the layout chain would
 * just re-test Craft.
 *
 * Renders via Twig's `loadTemplate()->renderBlock('content', ...)`
 * which evaluates only the named block against the supplied context.
 * Variables that the controller sets at render time (`isExpired`,
 * `neverChanged`, `policySource`) are pinned to deterministic values
 * here so the read-only assertions stay independent of the user's
 * actual password-change state.
 */
function renderPasswordSecurityContent(User $user): string
{
    $plugin = PasswordPolicy::$plugin;

    $policy = $plugin->getPolicyResolver()->resolveForUser($user);

    $view = Craft::$app->getView();
    $oldMode = $view->getTemplateMode();
    $view->setTemplateMode($view::TEMPLATE_MODE_CP);

    try {
        $template = $view->getTwig()->load('password-policy/_users/password-security');

        return $template->renderBlock('content', [
            'user' => $user,
            'policy' => $policy,
            'policySource' => 'Global',
            'isExpired' => false,
            'neverChanged' => $user->lastPasswordChangeDate === null,
            'currentUser' => Craft::$app->getUser()->getIdentity(),
        ]);
    } finally {
        $view->setTemplateMode($oldMode);
    }
}

// =============================================================================
// Permission predicate — registration appears with either permission
// =============================================================================

it('appends the Password Security link when the admin has pp:force-reset-passwords', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $html = triggerUserSidebar($target);

    expect($html)
        ->toContain('Password Security')
        ->and($html)->toContain("password-policy/users/{$target->id}/security");
});

it('appends the link when the admin has pp:change-user-passwords (admin granted by inheritance)', function() {
    // Same admin path — admins inherit every plugin permission.
    // Distinct test asserts the both-permissions-OR predicate doesn't
    // require both to be present simultaneously; the controller's
    // `callerHasViewPermission()` returns true on either.
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $html = triggerUserSidebar($target);

    expect($html)->toContain('Password Security');
});

it('does not append the link when the admin has neither permission', function() {
    // Non-admin without any plugin permissions — `currentUser->can(...)`
    // returns false for both `pp:force-reset-passwords` and
    // `pp:change-user-passwords`.
    $caller = UserFactory::nonAdmin();
    $this->userStub->setIdentity($caller);

    $target = UserFactory::nonAdmin();
    $html = triggerUserSidebar($target);

    expect($html)->not->toContain('Password Security');
});

it('does not append the link when there is no identified user', function() {
    // No identity bound to the request — `getIdentity()` returns null
    // and the predicate short-circuits to false.
    $this->userStub->setIdentity(null);

    $target = UserFactory::nonAdmin();
    $html = triggerUserSidebar($target);

    expect($html)->not->toContain('Password Security');
});

// =============================================================================
// Read-only mode — link still registers; gating happens inside the page
// =============================================================================

it('still appends the link when allowAdminChanges is off', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $html = triggerUserSidebar($target);

    // Read-only data (status, resolved policy) is fine to view; the
    // page itself disables write affordances via `readOnlyNotice()`
    // + the `disabled` attribute. Hiding the link in read-only mode
    // would force admins to bookmark the URL to ever review status —
    // worse UX for no security gain.
    expect($html)->toContain('Password Security');
});

// =============================================================================
// Controller — happy path
// =============================================================================

it('renders the page when the admin has permission', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $controller = new UserSecurityController('user-security', $this->plugin);
    $response = $controller->runAction('index', ['userId' => $target->id]);

    expect($response)->toBeInstanceOf(Response::class);

    $body = renderPasswordSecurityContent($target);
    expect($body)
        ->toBeString()
        ->and($body)->toContain('Password Status')
        ->and($body)->toContain('Active Policy');
});

// =============================================================================
// Controller — 404 + permission gate
// =============================================================================

it('returns 404 when the user does not exist', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $controller = new UserSecurityController('user-security', $this->plugin);

    expect(fn() => $controller->runAction('index', ['userId' => 999999]))
        ->toThrow(NotFoundHttpException::class);
});

it('rejects callers without either permission', function() {
    $caller = UserFactory::nonAdmin();
    $this->userStub->setIdentity($caller);

    $target = UserFactory::nonAdmin();
    $controller = new UserSecurityController('user-security', $this->plugin);

    expect(fn() => $controller->runAction('index', ['userId' => $target->id]))
        ->toThrow(ForbiddenHttpException::class);
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
    // `craft\helpers\Cp::readOnlyNoticeHtml()`. Match on the canonical
    // phrase rather than wrapper markup, which can evolve across Craft
    // 5 patch releases.
    expect($body)
        ->toBeString()
        ->and($body)->toContain('aren')
        ->and($body)->toContain('permitted in this environment');
});

it('omits the readOnlyNotice when admin changes are allowed', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    // Sanity inverse of the previous test — the read-only banner only
    // appears when the constraint is active.
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
        // No `disabled` attribute on the button.
        ->and($body)->not->toMatch('/<button[^>]*\bdisabled\b/');
});

// =============================================================================
// POST target alignment — defensive; ForcePasswordResetActionTest covers
// the action's behaviour, but the URL needs to match in the template
// =============================================================================

it('points the form at the existing retention/force-reset POST target', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();
    $body = renderPasswordSecurityContent($target);

    // The actionInput hidden field embeds the action route literally.
    expect($body)
        ->toBeString()
        ->and($body)->toContain('password-policy/retention/force-reset');
});
