<?php

use craftpulse\passwordpolicy\models\GroupPolicyModel;
use craftpulse\passwordpolicy\models\SettingsModel;

beforeEach(function() {
    $this->global = new SettingsModel();
});

it('inherits global values when group policy is all null', function() {
    $group = new GroupPolicyModel();
    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minLength)->toBe($this->global->minLength)
        ->and($merged->maxLength)->toBe($this->global->maxLength)
        ->and($merged->cases)->toBe($this->global->cases);
});

it('applies highest value for integer minimums', function() {
    $this->global->minLength = 8;

    $group = new GroupPolicyModel();
    $group->minLength = 12;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minLength)->toBe(12);
});

it('keeps global when global integer minimum is higher', function() {
    $this->global->minLength = 16;

    $group = new GroupPolicyModel();
    $group->minLength = 8;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->minLength)->toBe(16);
});

it('applies lowest non-zero value for integer maximums', function() {
    $this->global->maxLength = 128;

    $group = new GroupPolicyModel();
    $group->maxLength = 64;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->maxLength)->toBe(64);
});

it('treats zero maxLength as no limit', function() {
    $this->global->maxLength = 0;

    $group = new GroupPolicyModel();
    $group->maxLength = 128;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->maxLength)->toBe(128);
});

it('applies true wins for booleans', function() {
    $this->global->cases = false;

    $group = new GroupPolicyModel();
    $group->cases = true;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->cases)->toBeTrue();
});

it('does not let group false weaken global true', function() {
    $this->global->cases = true;

    $group = new GroupPolicyModel();
    $group->cases = false;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->cases)->toBeTrue();
});

it('applies individual complexity mode over minimum', function() {
    $this->global->complexityMode = 'minimum';

    $group = new GroupPolicyModel();
    $group->complexityMode = 'individual';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->complexityMode)->toBe('individual');
});

it('applies shortest expiration period', function() {
    $this->global->expiryAmount = 180;
    $this->global->expiryPeriod = 'day';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 90;
    $group->expiryPeriod = 'day';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(90);
});

it('keeps global when global expiration is shorter', function() {
    $this->global->expiryAmount = 30;
    $this->global->expiryPeriod = 'day';

    $group = new GroupPolicyModel();
    $group->expiryAmount = 90;
    $group->expiryPeriod = 'day';

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->expiryAmount)->toBe(30);
});

it('applies highest value for password history count', function() {
    $this->global->passwordHistoryCount = 5;

    $group = new GroupPolicyModel();
    $group->passwordHistoryCount = 12;

    $merged = $group->mergeWithGlobal($this->global);

    expect($merged->passwordHistoryCount)->toBe(12);
});

it('does not mutate the global settings model', function() {
    $this->global->minLength = 8;

    $group = new GroupPolicyModel();
    $group->minLength = 12;

    $group->mergeWithGlobal($this->global);

    expect($this->global->minLength)->toBe(8);
});
