<?php
/**
 * Pest coverage for the per-user action-menu items the plugin appends to the
 * "…" disclosure menu on the User edit screen, via
 * `Element::EVENT_DEFINE_ACTION_MENU_ITEMS`.
 *
 * Three items can appear: "Force password reset" (Pro,
 * `pp:user-force-reset`), "Send password reset email"
 * (`pp:change-user-passwords`), and "Change password…"
 * (`pp:change-user-passwords` plus the peer-admin gate).
 *
 * The peer-admin assertions are the reason this file exists. A non-admin
 * holding `pp:change-user-passwords` must not be offered "Change password…" on
 * an administrator's edit screen: `UserPasswordController::actionChange()`
 * answers that POST with a 403, and a menu that offers a button its own
 * handler refuses is a defect. The security boundary is the controller's, and
 * it is pinned in `UserPasswordControllerTest`; what is pinned here is that the
 * two agree.
 *
 * "Send password reset email" is deliberately NOT peer-gated, and that is
 * asserted too, because it is the kind of asymmetry a later reader would
 * otherwise "tidy up". It mails a reset link to the target's own address rather
 * than replacing the credential, so it crosses no privilege boundary, and Craft
 * core lets any holder of `editUsers` send one to an admin.
 *
 * The listener registers JS when it adds the modal item, which is why the
 * console-bootstrap CP trifecta applies here (see `PasswordSecurityTabTest`):
 * `UserStub`, a CP-shaped `WebRequestStub`, and the pinned
 * `assetManager.basePath` in `tests/_craft/config/app.php`.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\base\Element;
use craft\elements\User;
use craft\events\DefineMenuItemsEvent;
use craft\web\Response;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\PermissionFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

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
 * Fires `Element::EVENT_DEFINE_ACTION_MENU_ITEMS` on `$editedUser` the way
 * `Element::getActionMenuItems()` does mid-render, and returns the labels the
 * plugin's listener appended.
 *
 * Labels rather than whole items: the item shapes differ (an `action` + `params`
 * POST item versus a JS-driven `id` item), and what these tests care about is
 * which affordances a given actor is offered.
 *
 * @return string[]
 */
function fireUserActionMenuLabels(User $editedUser): array
{
    $event = new DefineMenuItemsEvent(['items' => []]);

    $editedUser->trigger(Element::EVENT_DEFINE_ACTION_MENU_ITEMS, $event);

    return array_values(array_filter(array_map(
        fn(array $item): ?string => $item['label'] ?? null,
        $event->items,
    )));
}

// =============================================================================
// Peer-admin gate on the password-set affordance
// =============================================================================

it('does not offer Change password to a non-admin looking at an admin', function() {
    $actor = PermissionFactory::nonAdminWith(['pp:change-user-passwords']);
    $this->userStub->setIdentity($actor);

    $labels = fireUserActionMenuLabels(UserFactory::admin());

    // The POST behind this item answers 403 for this actor and target pair, so
    // the item must not be there to click.
    expect($labels)->not->toContain('Change password…');
});

it('still offers Send password reset email to a non-admin looking at an admin', function() {
    // Not peer-gated on purpose. The mail goes to the target's own address, so
    // it replaces no credential and crosses no privilege boundary; core applies
    // the same rule to `UsersController::actionSendPasswordResetEmail()`.
    $actor = PermissionFactory::nonAdminWith(['pp:change-user-passwords']);
    $this->userStub->setIdentity($actor);

    $labels = fireUserActionMenuLabels(UserFactory::admin());

    expect($labels)->toContain('Send password reset email');
});

it('offers Change password to a non-admin looking at a non-admin', function() {
    // The gate closes one boundary and must not narrow the capability the
    // permission is for.
    $actor = PermissionFactory::nonAdminWith(['pp:change-user-passwords']);
    $this->userStub->setIdentity($actor);

    $labels = fireUserActionMenuLabels(UserFactory::nonAdmin());

    expect($labels)->toContain('Change password…');
});

it('offers Change password to an admin looking at another admin', function() {
    // Co-administrators are peers, which is the same rule the controller's
    // guard applies.
    $this->userStub->setIdentity(UserFactory::admin());

    $labels = fireUserActionMenuLabels(UserFactory::admin());

    expect($labels)->toContain('Change password…');
});

// =============================================================================
// The gates that were already in place
// =============================================================================

it('offers nothing when admin changes are disallowed', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->userStub->setIdentity(UserFactory::admin());

    expect(fireUserActionMenuLabels(UserFactory::nonAdmin()))->toBeEmpty();
});

it('offers nothing on a self-targeted edit screen', function() {
    // Admins set their own password through the standard account screen, which
    // is also what the controller enforces with a 400.
    $actor = UserFactory::admin();
    $this->userStub->setIdentity($actor);

    expect(fireUserActionMenuLabels($actor))->toBeEmpty();
});

it('offers nothing to a caller holding neither permission', function() {
    $this->userStub->setIdentity(UserFactory::nonAdmin());

    expect(fireUserActionMenuLabels(UserFactory::nonAdmin()))->toBeEmpty();
});
