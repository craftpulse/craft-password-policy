<?php

use craftpulse\passwordpolicy\enums\PolicyPreset;

it('configures NIST 800-63B preset correctly', function() {
    $policy = PolicyPreset::NIST_800_63B->toGroupPolicy();

    expect($policy->minLength)->toBe(8)
        ->and($policy->pwned)->toBeTrue()
        ->and($policy->cases)->toBeFalse()
        ->and($policy->numbers)->toBeFalse()
        ->and($policy->symbols)->toBeFalse()
        ->and($policy->expiryAmount)->toBeNull();
});

it('configures OWASP ASVS preset correctly', function() {
    $policy = PolicyPreset::OWASP_ASVS->toGroupPolicy();

    expect($policy->minLength)->toBe(12)
        ->and($policy->maxLength)->toBe(128)
        ->and($policy->pwned)->toBeTrue()
        ->and($policy->cases)->toBeFalse()
        ->and($policy->expiryAmount)->toBeNull();
});

it('configures Strict Enterprise preset correctly', function() {
    $policy = PolicyPreset::STRICT_ENTERPRISE->toGroupPolicy();

    expect($policy->minLength)->toBe(12)
        ->and($policy->cases)->toBeTrue()
        ->and($policy->numbers)->toBeTrue()
        ->and($policy->symbols)->toBeTrue()
        ->and($policy->pwned)->toBeTrue()
        ->and($policy->passwordHistoryCount)->toBe(5)
        ->and($policy->checkSequentialChars)->toBeTrue()
        ->and($policy->checkRepeatedChars)->toBeTrue()
        ->and($policy->checkContextual)->toBeTrue()
        ->and($policy->checkCommonPasswords)->toBeTrue()
        ->and($policy->expiryAmount)->toBe(90)
        ->and($policy->expiryPeriod)->toBe('day');
});

it('configures PCI-DSS v4.0 preset correctly', function() {
    $policy = PolicyPreset::PCI_DSS_V4->toGroupPolicy();

    expect($policy->minLength)->toBe(12)
        ->and($policy->cases)->toBeTrue()
        ->and($policy->numbers)->toBeTrue()
        ->and($policy->pwned)->toBeTrue()
        ->and($policy->passwordHistoryCount)->toBe(4)
        ->and($policy->checkCommonPasswords)->toBeTrue()
        ->and($policy->expiryAmount)->toBe(90)
        ->and($policy->expiryPeriod)->toBe('day');
});

it('does not require symbols in PCI-DSS preset', function() {
    // PCI-DSS requires numeric + alphabetic, not symbols
    $policy = PolicyPreset::PCI_DSS_V4->toGroupPolicy();

    expect($policy->symbols)->toBeNull();
});

it('gives all presets labels', function() {
    foreach (PolicyPreset::cases() as $preset) {
        expect($preset->label())->not->toBeEmpty();
    }
});

it('sets the preset name on all group policies', function() {
    foreach (PolicyPreset::cases() as $preset) {
        $policy = $preset->toGroupPolicy();
        expect($policy->preset)->toBe($preset->value);
    }
});
