<?php
/**
 * Pest coverage for `UserIndexService::getAttributesForRegistration()` —
 * the edition matrix that decides which password-policy columns appear
 * in the Users element-index column picker.
 *
 * D2 ships nine columns gated by two independent axes: plugin edition
 * (Lite vs. Pro+) and Craft edition (Solo vs. Team or higher). The
 * tests assert each cell of the (plugin × Craft) matrix renders the
 * right column set.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\enums\CmsEdition;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;

// =============================================================================
// Setup / teardown — restore plugin + Craft edition between scenarios
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalPluginEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
});

afterEach(function() {
    $this->plugin->edition = $this->originalPluginEdition;
    Craft::$app->edition = $this->originalCraftEdition;
});

// =============================================================================
// Lite — six baseline columns regardless of Craft edition
// =============================================================================

it('registers the six Lite-tier columns on Lite + Solo', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    Craft::$app->edition = CmsEdition::Solo;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect(array_keys($attributes))->toEqual([
        UserIndexService::ATTR_LAST_CHANGE,
        UserIndexService::ATTR_DAYS_UNTIL_EXPIRY,
        UserIndexService::ATTR_EXPIRED,
        UserIndexService::ATTR_RESET_REQUIRED,
        UserIndexService::ATTR_STATUS,
        UserIndexService::ATTR_LAST_CHANGE_REASON,
    ]);
});

it('registers the same six columns on Lite + Pro Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    Craft::$app->edition = CmsEdition::Pro;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)->toHaveCount(6)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_BREACHED)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_POLICY_DRIFT)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_GROUP_POLICIES);
});

// =============================================================================
// Pro + Solo — adds breached, omits policy columns
// =============================================================================

it('adds the breached column on Pro + Solo Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Solo;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)->toHaveKey(UserIndexService::ATTR_BREACHED)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_POLICY_DRIFT)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_GROUP_POLICIES)
        ->and($attributes)->toHaveCount(7);
});

// =============================================================================
// Pro + Team or higher — full nine-column set
// =============================================================================

it('registers all nine columns on Pro + Team Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Team;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)->toHaveCount(9)
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_BREACHED)
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_POLICY_DRIFT)
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_GROUP_POLICIES);
});

it('registers all nine columns on Pro + Pro Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)->toHaveCount(9);
});

// =============================================================================
// Enterprise inherits Pro's gates — no further additions
// =============================================================================

it('matches Pro behaviour on Enterprise + Pro Craft', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    Craft::$app->edition = CmsEdition::Pro;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)->toHaveCount(9);
});

// =============================================================================
// Labels — every registered attribute carries a non-empty label
// =============================================================================

it('attaches a non-empty label to every attribute', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    foreach ($attributes as $key => $config) {
        expect($config)
            ->toHaveKey('label')
            ->and($config['label'])->not->toBeEmpty("attribute {$key} missing a label");
    }
});
