<?php
/**
 * Pest coverage for the cross-edition gating behaviour of
 * `UserIndexService` plus the read-only-mode contract that columns
 * still render when `allowAdminChanges = false`.
 *
 * Read-only mode (the absorbed P2.6 verification gate) is a quality
 * bar for D2 affordances: data display is fine in read-only, no
 * inline action triggers should fire. The columns shipped here have
 * no inline actions (D3 ships those), so the assertion is simply
 * "rendering still works."
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\enums\CmsEdition;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getUserIndex();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    // Pin a benign expiry config so the daysUntilExpiry + expired
    // columns register — `AttributeRegistrationTest` covers the
    // expiry-off path exhaustively; this file focuses on the edition
    // matrix without the expiry confound.
    $this->settings->expiryAmount = 90;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->edition = $this->originalCraftEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
    $this->service->resetCache();
});

// =============================================================================
// Plugin-edition gating — Lite cannot see Pro-only column registration
// =============================================================================

it('hides the breached column on Lite even with Pro Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    Craft::$app->edition = CmsEdition::Pro;

    $attributes = $this->service->getAttributesForRegistration();

    expect($attributes)->not->toHaveKey(UserIndexService::ATTR_BREACHED);
});

// =============================================================================
// Craft-edition gating — Solo hides the policy-related columns even on Pro
// =============================================================================

it('hides the policy columns on Pro plugin + Solo Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Solo;

    $attributes = $this->service->getAttributesForRegistration();

    expect($attributes)
        ->toHaveKey(UserIndexService::ATTR_BREACHED)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_POLICY_DRIFT)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_GROUP_POLICIES);
});

// =============================================================================
// Solo plugin-Pro: edition-helper sanity
// =============================================================================

it('reports isCraftSolo correctly on Solo', function() {
    Craft::$app->edition = CmsEdition::Solo;

    expect($this->plugin->isCraftSolo())->toBeTrue()
        ->and($this->plugin->isCraftTeamOrBetter())->toBeFalse();
});

it('reports isCraftTeamOrBetter correctly on Team', function() {
    Craft::$app->edition = CmsEdition::Team;

    expect($this->plugin->isCraftSolo())->toBeFalse()
        ->and($this->plugin->isCraftTeamOrBetter())->toBeTrue();
});

it('reports isCraftTeamOrBetter correctly on Pro', function() {
    Craft::$app->edition = CmsEdition::Pro;

    expect($this->plugin->isCraftSolo())->toBeFalse()
        ->and($this->plugin->isCraftTeamOrBetter())->toBeTrue();
});

// =============================================================================
// Read-only mode (`allowAdminChanges = false`)
// =============================================================================

it('still registers all columns when allowAdminChanges is off', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $attributes = $this->service->getAttributesForRegistration();

    expect($attributes)->toHaveCount(9);
});

it('still renders cell HTML when allowAdminChanges is off', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $user = UserFactory::admin();
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => Carbon::now('UTC')->subDays(2)->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();

    $this->service->preloadForUsers([$user->id]);

    foreach (UserIndexService::ATTRIBUTE_KEYS as $attribute) {
        $html = $this->service->renderAttributeHtml($user, $attribute);

        expect($html)->toBeString("attribute {$attribute} should still render in read-only mode");
    }
});
