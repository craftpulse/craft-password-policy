<?php
/**
 * Pest coverage for the ten deleted `siem*` / `webhooks` settings.
 *
 * They were declared on `SettingsModel`, stripped from a sub-Enterprise
 * save, and read by nothing. Five of them marked the HTTP SIEM
 * destination, which now lives on the forwarder row as real columns; the
 * other five described behaviour the plugin does not have. All ten are
 * gone.
 *
 * The risk in deleting a settings property is not the deletion, it is the
 * installs that already materialised the key. `SettingsController::actionSave`
 * merges the full existing attribute set before saving, so any install that
 * ever opened a settings screen has `siemEnabled: false` (and its nine
 * siblings) written into project config, and those keys stay in
 * `project.yaml` until something rewrites the block. Applying them must be
 * a silent no-op rather than an `UnknownPropertyException` on boot.
 *
 * `craft\base\Plugin::setSettings()` and `Plugins::savePluginSettings()`
 * both route through `Model::setAttributes($values, false)`, which only
 * assigns keys present in `attributes()` — so the guarantee is Yii's, and
 * this file pins it rather than assuming it.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\behaviors\EnvAttributeParserBehavior;
use craftpulse\passwordpolicy\models\SettingsModel;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup
// =============================================================================

/**
 * Every setting deleted in 5.2.0, with the value an existing install has
 * materialised in project config.
 */
function deletedSiemSettings(): array
{
    return [
        'siemEnabled' => false,
        'siemDestinationType' => 'syslog',
        'siemEndpointUrl' => null,
        'siemAuthType' => 'bearer',
        'siemAuthToken' => null,
        'siemCustomHeaders' => null,
        'siemIpHandling' => 'masked',
        'siemDeviceHandling' => 'label',
        'webhooksEnabled' => false,
        'webhooks' => [],
    ];
}

// =============================================================================
// The properties are gone
// =============================================================================

it('no longer declares any of the ten settings', function(string $attribute) {
    expect((new SettingsModel())->attributes())->not->toContain($attribute);
})->with(array_keys(deletedSiemSettings()));

it('no longer registers the two env-parsed ones on the parser behavior', function() {
    // `siemEndpointUrl` and `siemAuthToken` were listed on
    // `EnvAttributeParserBehavior`. The behavior resolves attributes by
    // name at validate time, so a stale entry would throw there.
    $behavior = (new SettingsModel())->getBehavior('parser');

    expect($behavior)->toBeInstanceOf(EnvAttributeParserBehavior::class);

    /** @var EnvAttributeParserBehavior $behavior */
    expect($behavior->attributes)->not->toContain('siemEndpointUrl')
        ->and($behavior->attributes)->not->toContain('siemAuthToken');
});

// =============================================================================
// An existing install's project config still applies
// =============================================================================

it('ignores the stale keys when project config is applied', function() {
    $plugin = PasswordPolicy::$plugin;
    $original = $plugin->getSettings()->minLength;

    try {
        // The shape `Plugins::createPlugin()` hands a plugin on boot: the
        // whole stored settings block, stale keys and all.
        $plugin->setSettings(deletedSiemSettings() + ['minLength' => 14]);

        expect($plugin->getSettings()->minLength)->toBe(14)
            // And the model is still valid, so the settings screen and
            // `savePluginSettings()` both keep working.
            ->and($plugin->getSettings()->validate())->toBeTrue();
    } finally {
        $plugin->setSettings(['minLength' => $original]);
    }
});

it('does not resurrect a deleted key as a dynamic property', function() {
    $settings = new SettingsModel();
    $settings->setAttributes(deletedSiemSettings(), false);

    expect($settings->toArray())->not->toHaveKey('siemEnabled')
        ->and($settings->toArray())->not->toHaveKey('webhooks');
});

// =============================================================================
// The strip block no longer names them
// =============================================================================

it('keeps the live Enterprise settings that replaced them in the strip block', function() {
    // The deletion removed ten `unset()` lines from
    // `SettingsController::_stripEditionGatedKeys()`. The seven live
    // SIEM/webhook settings must still be there, or a Lite install could
    // write them by curl.
    $source = file_get_contents(
        dirname(__DIR__, 3) . '/src/controllers/SettingsController.php',
    );

    expect($source)->toContain("\$settings['siemForwardEventClasses']")
        ->and($source)->toContain("\$settings['siemCircuitCooldownSeconds']")
        ->and($source)->toContain("\$settings['siemCircuitFailureThreshold']")
        ->and($source)->toContain("\$settings['webhookForwardEventClasses']")
        ->and($source)->toContain("\$settings['webhookCircuitCooldownSeconds']")
        ->and($source)->toContain("\$settings['webhookCircuitFailureThreshold']")
        ->and($source)->toContain("\$settings['webhookSecretGracePeriodHours']")
        // And none of the deleted ones.
        ->and($source)->not->toContain("\$settings['siemEnabled']")
        ->and($source)->not->toContain("\$settings['webhooks']");
});
