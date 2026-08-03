<?php
/**
 * Pest coverage for the hide-not-badge edition doctrine on the two surfaces a
 * lower edition would otherwise advertise higher-edition features through:
 *
 *  1. The permissions screen. Every permission that gates a Pro or Enterprise
 *     screen registers only on that edition, so a Lite admin's permission list
 *     never offers a grant that leads nowhere.
 *  2. The CP subnav. Every higher-edition entry is absent below its edition,
 *     never rendered disabled and never badged.
 *
 * Both are asserted at the registration boundary (`EVENT_REGISTER_PERMISSIONS`
 * for the first, `getCpNavItem()` for the second) rather than through rendered
 * markup, so the assertions pin the decision rather than the styling.
 *
 * The acting identity is an admin throughout: admins clear every `can()` check,
 * which leaves the edition as the only thing that can hide an entry. That's
 * what makes these tests about edition gating and not about permissions.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\events\RegisterUserPermissionsEvent;
use craft\services\UserPermissions;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use yii\base\Event;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalUser = Craft::$app->getUser();
    $this->originalPerGroup = $this->plugin->getSettings()->enablePerGroupPolicies;

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);
    $this->userStub->setIdentity(UserFactory::admin());
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enablePerGroupPolicies = $this->originalPerGroup;
    Craft::$app->set('user', $this->originalUser);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Fires `UserPermissions::EVENT_REGISTER_PERMISSIONS` and returns the flat list
 * of permission handles the plugin contributed, nested children included.
 *
 * Reads the event rather than `UserPermissions::getAllPermissions()` because
 * that method memoizes into a private property with no reset, so a second call
 * after an edition switch would return the first edition's tree.
 *
 * @return string[]
 */
function ppRegisteredPermissionHandles(): array
{
    $event = new RegisterUserPermissionsEvent();
    Event::trigger(UserPermissions::class, UserPermissions::EVENT_REGISTER_PERMISSIONS, $event);

    $handles = [];

    foreach ($event->permissions as $group) {
        if (($group['heading'] ?? null) !== 'Password Policy') {
            continue;
        }

        foreach ($group['permissions'] as $handle => $definition) {
            $handles[] = $handle;

            foreach (array_keys($definition['nested'] ?? []) as $nestedHandle) {
                $handles[] = $nestedHandle;
            }
        }
    }

    return $handles;
}

/**
 * Returns the subnav keys `getCpNavItem()` exposes for the current edition.
 *
 * @return string[]
 */
function ppSubnavKeys(): array
{
    return array_keys(PasswordPolicy::$plugin->getCpNavItem()['subnav'] ?? []);
}

// =============================================================================
// Permissions — universal handles register on every edition
// =============================================================================

it('registers the universal permissions on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(ppRegisteredPermissionHandles())->toContain(
        PasswordPolicy::PERMISSION_MANAGE_SETTINGS,
        'pp:change-user-passwords',
    );
});

it('registers the mass force-reset permission on Lite', function() {
    // Regression pin. The mass force-reset path (the Password Retention
    // utility's action and the `retention/force-reset-passwords` console
    // command) shipped in 5.1.2, before the plugin had editions, so every
    // install updating into 5.2.0 already holds `pp:force-reset-passwords` and
    // every one of them resolves to Lite by default. Registering the handle
    // behind Pro would silently withdraw a capability those installs already
    // paid for, and the permissions screen would stop offering the grant that
    // gates a utility still sitting in their Utilities list.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(ppRegisteredPermissionHandles())
        ->toContain(PasswordPolicy::PERMISSION_FORCE_RESET_PASSWORDS);
});

it('registers the mass force-reset permission on Pro and Enterprise too', function() {
    // Universal means universal: the handle is not swapped out for the per-user
    // one higher up the ladder, because the two capabilities coexist.
    foreach ([PasswordPolicy::EDITION_PRO, PasswordPolicy::EDITION_ENTERPRISE] as $edition) {
        $this->plugin->edition = $edition;

        expect(ppRegisteredPermissionHandles())
            ->toContain(PasswordPolicy::PERMISSION_FORCE_RESET_PASSWORDS);
    }
});

// =============================================================================
// Permissions — Pro handles are absent below Pro
// =============================================================================

it('does not register the Pro permissions on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $handles = ppRegisteredPermissionHandles();

    expect($handles)->not->toContain('pp:blocklist-view')
        ->and($handles)->not->toContain('pp:blocklist-manage')
        ->and($handles)->not->toContain('pp:notification-templates-manage')
        ->and($handles)->not->toContain('pp:notification-log-view')
        ->and($handles)->not->toContain('pp:inactive-view')
        // PER-USER force reset is Pro on every surface it has (bulk element
        // action, user-edit action menu, Password Security pane), so offering
        // the grant on Lite would point at nothing. The MASS handle is a
        // separate, universal permission and is asserted present above.
        ->and($handles)->not->toContain(PasswordPolicy::PERMISSION_USER_FORCE_RESET);
});

it('registers the Pro permissions on Pro, nested child included', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    expect(ppRegisteredPermissionHandles())->toContain(
        'pp:blocklist-view',
        'pp:blocklist-manage',
        'pp:notification-templates-manage',
        'pp:notification-log-view',
        'pp:inactive-view',
        PasswordPolicy::PERMISSION_USER_FORCE_RESET,
    );
});

// =============================================================================
// Permissions — Enterprise handles are absent below Enterprise
// =============================================================================

it('does not register the Enterprise permissions on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $handles = ppRegisteredPermissionHandles();

    expect($handles)->not->toContain('pp:audit-view')
        ->and($handles)->not->toContain('pp:audit-verify')
        ->and($handles)->not->toContain('pp:audit-export')
        ->and($handles)->not->toContain('pp:siem-manage')
        ->and($handles)->not->toContain('pp:webhooks-manage')
        ->and($handles)->not->toContain('pp:api-manage');
});

it('registers the Enterprise permissions on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    expect(ppRegisteredPermissionHandles())->toContain(
        'pp:audit-view',
        'pp:audit-verify',
        'pp:audit-export',
        'pp:siem-manage',
        'pp:webhooks-manage',
        'pp:api-manage',
    );
});

// =============================================================================
// CP subnav — higher-edition entries are absent, never disabled
// =============================================================================

it('exposes no subnav at all on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->plugin->getSettings()->enablePerGroupPolicies = true;

    // `enablePerGroupPolicies` is on, so anything hiding the Pro entries here
    // is the edition gate and nothing else. Settings is the only survivor, and
    // `getCpNavItem()` collapses a single-entry subnav to none (the nav item
    // itself already links there), so Lite shows a bare "Password Policy" item
    // with no higher-edition children hinted at.
    expect(ppSubnavKeys())->toBe([]);
});

it('adds the Pro subnav entries on Pro and no Enterprise ones', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enablePerGroupPolicies = true;

    $keys = ppSubnavKeys();

    expect($keys)->toContain(
        'policies',
        'blocklist',
        'inactive-accounts',
        'notifications',
        'notification-activity',
        'group-alerts',
        'settings',
    );

    expect($keys)->not->toContain('siem-forwarders')
        ->and($keys)->not->toContain('webhooks')
        ->and($keys)->not->toContain('api-tokens');
});

it('adds the Enterprise subnav entries on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    expect(ppSubnavKeys())->toContain(
        'siem-forwarders',
        'webhooks',
        'api-tokens',
        'settings',
    );
});
