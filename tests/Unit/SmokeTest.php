<?php
/**
 * Smoke test — verifies Pest itself is wired and runnable without Craft
 * boot. If this fails, the suite isn't installed correctly; everything
 * else is downstream of this passing.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

it('runs Pest', function() {
    expect(1 + 1)->toBe(2);
});
