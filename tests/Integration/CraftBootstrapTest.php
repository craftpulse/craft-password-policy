<?php
/**
 * Bootstrap proof — verifies that `tests/bootstrap.php` brought Craft
 * online, installed the schema, registered the plugin, and bound the
 * `hibpClient` service. If this passes, every Phase E2-E6 sub-suite
 * has a known-good baseline to build on.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use Craft;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\HibpClientInterface;

it('boots Craft', function() {
    expect(Craft::$app)->not->toBeNull();
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
