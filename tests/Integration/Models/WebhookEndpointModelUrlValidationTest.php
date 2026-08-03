<?php
/**
 * Pest coverage for `WebhookEndpointModel`'s URL validation rule.
 *
 * Pins the hardening contract: a webhook carries an HMAC-signed payload
 * and must never traverse plaintext http. The model rule sets
 * `validSchemes => ['https']` so an explicit `http://` URL is rejected
 * outright; a scheme-less host is normalised to https via
 * `defaultScheme`; an env-var reference (`$VAR`) skips the rule (resolved
 * + re-checked at dispatch time).
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\WebhookEndpointModel;

// =============================================================================
// https-only scheme enforcement
// =============================================================================

it('accepts an explicit https:// URL', function() {
    $model = new WebhookEndpointModel();
    $model->url = 'https://hooks.example.test/audit';

    expect($model->validate(['url']))->toBeTrue();
    expect($model->getErrors('url'))->toBeEmpty();
});

it('rejects an explicit http:// URL', function() {
    $model = new WebhookEndpointModel();
    $model->url = 'http://insecure.example.test/audit';

    expect($model->validate(['url']))->toBeFalse();
    expect($model->getErrors('url'))->not->toBeEmpty();
});

it('skips URL validation for an env-var reference', function() {
    // Resolution + scheme re-check happens at dispatch; the model rule
    // intentionally short-circuits on a `$`-prefixed value.
    $model = new WebhookEndpointModel();
    $model->url = '$PP_WEBHOOK_URL';

    expect($model->validate(['url']))->toBeTrue();
    expect($model->getErrors('url'))->toBeEmpty();
});

it('rejects an empty URL as required', function() {
    $model = new WebhookEndpointModel();
    $model->url = '';

    expect($model->validate(['url']))->toBeFalse();
    expect($model->getErrors('url'))->not->toBeEmpty();
});
