<?php
/**
 * Pest coverage for `WebhookEndpointModel::fields()` — the serialization
 * boundary that keeps the plaintext HMAC secret out of every
 * `asModelSuccess` JSON response.
 *
 * Pins the contract: `toArray()` (which Yii calls via `asModelSuccess`)
 * never returns `secretCurrent` or `secretPrevious`. The model's
 * encryption boundary holds plaintext for service-layer use; the
 * serialization boundary keeps it off the wire.
 *
 * Regression coverage: prior to the fields() exclusion,
 * `WebhookEndpointController::actionSave` returned the decrypted
 * secrets in every edit-save JSON response — once-and-only-once on
 * create became forever-on-every-edit.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\WebhookEndpointModel;

// =============================================================================
// Plaintext secrets are excluded from the default serialization surface
// =============================================================================

it('excludes secretCurrent from toArray()', function() {
    $model = new WebhookEndpointModel();
    $model->url = 'https://example.test/webhook';
    $model->secretCurrent = 'plaintext-active-secret-do-not-leak';

    expect($model->toArray())->not->toHaveKey('secretCurrent');
});

it('excludes secretPrevious from toArray()', function() {
    $model = new WebhookEndpointModel();
    $model->url = 'https://example.test/webhook';
    $model->secretPrevious = 'plaintext-previous-secret-do-not-leak';

    expect($model->toArray())->not->toHaveKey('secretPrevious');
});

it('still exposes operational fields (url, enabled, name) via toArray()', function() {
    $model = new WebhookEndpointModel();
    $model->url = 'https://example.test/webhook';
    $model->name = 'Test endpoint';
    $model->enabled = true;

    $serialized = $model->toArray();

    expect($serialized)->toHaveKey('url');
    expect($serialized)->toHaveKey('name');
    expect($serialized)->toHaveKey('enabled');
    expect($serialized['url'])->toBe('https://example.test/webhook');
});
