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
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\enums\CmsEdition;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;

// =============================================================================
// Setup / teardown — restore plugin + Craft edition + expiry config
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();
    $this->originalPluginEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    // Pin a benign expiry config so the daysUntilExpiry + expired
    // columns register. The expiry-off case is covered in its own
    // test below.
    $this->settings->expiryAmount = 90;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->plugin->edition = $this->originalPluginEdition;
    Craft::$app->edition = $this->originalCraftEdition;
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
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
// Expiry-configured gate — drops daysUntilExpiry + expired when off
// =============================================================================

it('drops the expiry columns when expiryAmount is null', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;
    $this->settings->expiryAmount = null;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)
        ->not->toHaveKey(UserIndexService::ATTR_DAYS_UNTIL_EXPIRY)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_EXPIRED)
        // Status, reset-required, last-change, last-change-reason still
        // register — those work without an expiry threshold (status
        // resolves to never_changed/ok/breached/reset_required).
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_STATUS)
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_RESET_REQUIRED)
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_LAST_CHANGE)
        ->and($attributes)->toHaveKey(UserIndexService::ATTR_LAST_CHANGE_REASON)
        ->and($attributes)->toHaveCount(7);
});

it('drops the expiry columns on Lite when expiryAmount is null', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    Craft::$app->edition = CmsEdition::Pro;
    $this->settings->expiryAmount = null;

    $attributes = $this->plugin->getUserIndex()->getAttributesForRegistration();

    expect($attributes)->toHaveCount(4)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_DAYS_UNTIL_EXPIRY)
        ->and($attributes)->not->toHaveKey(UserIndexService::ATTR_EXPIRED);
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
