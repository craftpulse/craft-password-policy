<?php
/**
 * Test-suite Guzzle config.
 *
 * `Craft::createGuzzleClient()` reads this file on every call and merges
 * the returned array into the request config. The `TestGuzzleConfig`
 * holder lets individual tests install a `MockHandler`-backed stack via
 * `TestGuzzleConfig::setMockHandler($mock)`; the next `createGuzzleClient`
 * call splices the mock into the handler chain. `null` means "fall back
 * to Guzzle's default cURL handler" — every non-mocked test path.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use craftpulse\passwordpolicy\tests\Support\TestGuzzleConfig;

if (TestGuzzleConfig::$handler === null) {
    return [];
}

return [
    'handler' => TestGuzzleConfig::$handler,
];
