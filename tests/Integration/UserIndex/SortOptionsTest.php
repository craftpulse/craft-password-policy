<?php
/**
 * Pest coverage for `UserIndexService::getSortOptions()` and the paired
 * `getSortMapping()` resolver. Only cheap-to-sort columns appear in the
 * Users element index sort menu — composite/subquery-based columns are
 * deliberately absent to avoid surprising query costs.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getUserIndex();
    $this->settings = PasswordPolicy::$plugin->getSettings();
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    // Pin a benign expiry config so the daysUntilExpiry + expired
    // sort options are present. The expiry-off case is a separate
    // assertion below.
    $this->settings->expiryAmount = 90;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
});

// =============================================================================
// Sortable column inventory
// =============================================================================

it('exposes the four cheap-to-sort columns', function() {
    $options = $this->service->getSortOptions();

    expect(array_keys($options))->toEqual([
        UserIndexService::ATTR_LAST_CHANGE,
        UserIndexService::ATTR_DAYS_UNTIL_EXPIRY,
        UserIndexService::ATTR_EXPIRED,
        UserIndexService::ATTR_RESET_REQUIRED,
    ]);
});

it('excludes composite and subquery columns', function() {
    $options = $this->service->getSortOptions();

    expect($options)->not->toHaveKey(UserIndexService::ATTR_STATUS)
        ->and($options)->not->toHaveKey(UserIndexService::ATTR_LAST_CHANGE_REASON)
        ->and($options)->not->toHaveKey(UserIndexService::ATTR_BREACHED)
        ->and($options)->not->toHaveKey(UserIndexService::ATTR_POLICY_DRIFT)
        ->and($options)->not->toHaveKey(UserIndexService::ATTR_GROUP_POLICIES);
});

// =============================================================================
// Mapping resolution
// =============================================================================

it('maps the date-based columns to the lastPasswordChangeDate column', function() {
    foreach ([
        UserIndexService::ATTR_LAST_CHANGE,
        UserIndexService::ATTR_DAYS_UNTIL_EXPIRY,
        UserIndexService::ATTR_EXPIRED,
    ] as $attribute) {
        $mapping = $this->service->getSortMapping($attribute);

        expect($mapping)
            ->not->toBeNull()
            ->and(array_keys($mapping))->toContain('users.lastPasswordChangeDate');
    }
});

it('maps the reset-required column to the boolean column', function() {
    $mapping = $this->service->getSortMapping(UserIndexService::ATTR_RESET_REQUIRED);

    expect($mapping)
        ->not->toBeNull()
        ->and(array_keys($mapping))->toContain('users.passwordResetRequired');
});

it('returns null for unsortable columns', function() {
    foreach ([
        UserIndexService::ATTR_STATUS,
        UserIndexService::ATTR_LAST_CHANGE_REASON,
        UserIndexService::ATTR_BREACHED,
        UserIndexService::ATTR_POLICY_DRIFT,
        UserIndexService::ATTR_GROUP_POLICIES,
        'unrelated_attribute',
    ] as $attribute) {
        expect($this->service->getSortMapping($attribute))->toBeNull();
    }
});

it('drops the expiry-dependent sort options when expiry is not configured', function() {
    $this->settings->expiryAmount = null;

    $options = $this->service->getSortOptions();

    expect(array_keys($options))->toEqual([
        UserIndexService::ATTR_LAST_CHANGE,
        UserIndexService::ATTR_RESET_REQUIRED,
    ]);
});
