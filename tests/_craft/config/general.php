<?php
/**
 * General config for the Pest test suite. Keeps devMode on so traces surface
 * in fixture failures, and disables the queue auto-run so jobs stay in the
 * queue table for assertions instead of executing inline.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use craft\helpers\App;

return [
    'devMode' => true,
    'allowAdminChanges' => true,
    'runQueueAutomatically' => false,
    'securityKey' => App::env('CRAFT_SECURITY_KEY') ?: 'test-key-do-not-use-in-production-ever-zZ9',
];
