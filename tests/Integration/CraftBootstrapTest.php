<?php
/**
 * Bootstrap proof — verifies that `tests/bootstrap.php` brought Craft
 * online, installed the schema, registered the plugin, and bound the
 * `hibpClient` service. If this passes, every Phase E2-E6 sub-suite
 * has a known-good baseline to build on.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use Craft;
use craftpulse\auditkit\AuditKit;
use craftpulse\auditkit\services\Bus;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\HibpClientInterface;

it('boots Craft', function() {
    expect(Craft::$app)->not->toBeNull();
});

it('attaches the Audit Kit module and a live dispatch bus', function() {
    // Behavioural counterpart to `tests/Unit/AuditKitRetrofitTest.php`. It
    // cannot isolate PP's own `AuditKit::register()` call — `tests/bootstrap.php`
    // registers the module too, and on a real install any other kit consumer
    // would — so the token scan there is what guards the call itself. This pins
    // the outcome the whole retrofit exists to produce: a constructed module and
    // a resolvable bus.
    expect(Craft::$app->getModule(AuditKit::ID))->toBeInstanceOf(AuditKit::class);
    expect(AuditKit::getInstance()->getBus())->toBeInstanceOf(Bus::class);
});

it('installed the password-policy plugin', function() {
    $plugins = Craft::$app->getPlugins();

    expect($plugins->isPluginInstalled('password-policy'))->toBeTrue()
        ->and($plugins->isPluginEnabled('password-policy'))->toBeTrue()
        ->and(PasswordPolicy::getInstance())->not->toBeNull();
});

it('created all seven plugin tables', function() {
    $expected = [
        '{{%passwordpolicy_audit_log}}',
        '{{%passwordpolicy_blocklist}}',
        '{{%passwordpolicy_notification_log}}',
        '{{%passwordpolicy_notification_templates}}',
        '{{%passwordpolicy_password_history}}',
        '{{%passwordpolicy_policies}}',
        '{{%passwordpolicy_policy_groups}}',
    ];

    $schema = Craft::$app->getDb()->getSchema();

    foreach ($expected as $table) {
        expect($schema->getTableSchema($table))
            ->not->toBeNull("Plugin table {$table} missing from db_test schema.");
    }
});

it('binds the hibpClient service to HibpClientInterface', function() {
    $client = PasswordPolicy::$plugin->getHibpClient();

    expect($client)->toBeInstanceOf(HibpClientInterface::class);
});
