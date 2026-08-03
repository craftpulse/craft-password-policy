<?php
/**
 * Database connection for the Pest test suite. Reads env vars set by
 * `phpunit.xml.dist` so the test DB stays isolated from the playground's
 * primary database.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use craft\helpers\App;

return [
    'driver' => App::env('CRAFT_DB_DRIVER') ?: 'mysql',
    'server' => App::env('CRAFT_DB_SERVER') ?: 'db',
    'port' => App::env('CRAFT_DB_PORT') ?: 3306,
    'database' => App::env('CRAFT_DB_DATABASE') ?: 'db_test',
    'user' => App::env('CRAFT_DB_USER') ?: 'db',
    'password' => App::env('CRAFT_DB_PASSWORD') ?: 'db',
    'schema' => App::env('CRAFT_DB_SCHEMA') ?: 'public',
    'tablePrefix' => App::env('CRAFT_DB_TABLE_PREFIX') ?: '',
];
