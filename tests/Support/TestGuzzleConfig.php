<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;

/**
 * Static holder for a per-test Guzzle handler stack.
 *
 * `Craft::createGuzzleClient()` reads `config/guzzle.php` on every call
 * and merges it into the request config. The fixture `guzzle.php` shipped
 * for the test suite reads the handler from this holder so individual
 * tests can install a `MockHandler` queue, run the code under test, and
 * reset.
 *
 * Why a static holder rather than DI: `GuzzleHibpClient::query()` builds
 * its client mid-method via `Craft::createGuzzleClient()` — the Guzzle
 * `Client` instance is never visible at the boundary. The only injection
 * point is the global config file path. A static holder keeps the
 * coupling explicit and the reset path obvious.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class TestGuzzleConfig
{
    // Static Properties
    // =========================================================================

    /**
     * The handler stack to splice into every Craft Guzzle client until
     * cleared. `null` means "use the real default handler" — production
     * behavior. Tests `set()` a `MockHandler`-backed stack at the top of
     * the test and `clear()` it in `afterEach`.
     *
     * @var HandlerStack|null
     *
     * @since 5.2.0
     */
    public static ?HandlerStack $handler = null;

    // Static Methods
    // =========================================================================

    /**
     * Builds a `HandlerStack` around the supplied `MockHandler` and stores
     * it for the next `Craft::createGuzzleClient()` to pick up.
     *
     * @param MockHandler $handler
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function setMockHandler(MockHandler $handler): void
    {
        self::$handler = HandlerStack::create($handler);
    }

    /**
     * Clears the test handler so subsequent calls fall back to the real
     * Guzzle handler stack. Tests MUST call this in `afterEach` — leaving
     * a handler set across tests would leak the previous test's queued
     * responses into the next.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function clear(): void
    {
        self::$handler = null;
    }
}
