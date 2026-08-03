<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use Craft;
use craft\elements\User;
use craft\mail\Mailer;

/**
 * Pins the application mailer into a state where `send()` actually succeeds,
 * and puts it back afterwards.
 *
 * Two things make the as-installed test mailer unusable:
 *
 * 1. **No `email` project config.** `craft\migrations\Install` seeds
 *    `email.fromEmail` / `fromName` / `transportType` through
 *    `ProjectConfig::applyConfigChanges()`, but the internal config is only
 *    flushed to the `projectconfig` table on `Application::EVENT_AFTER_REQUEST`
 *    — an event a console test process never fires. So every subsequent test
 *    process reads `ProjectConfig::get('email')` as `null`, `App::mailerConfig()`
 *    falls back to an empty `MailSettings`, and `Mailer::$from` ends up as
 *    `['' => null]`. `yii\symfonymailer\Message::setFrom()` hands that null
 *    straight to `Symfony\Component\Mime\Address::__construct()`, whose `$name`
 *    argument is a non-nullable `string` — so composing ANY message throws a
 *    `TypeError` before a transport is ever consulted.
 *
 * 2. **`useFileTransport` is off**, so a send that got past (1) would shell out
 *    to a sendmail binary that isn't there.
 *
 * Any test that asserts on a successful send therefore has to configure the
 * mailer itself. Before this fixture existed, four `Integration/Services`
 * notification files silently relied on `Integration/Controllers` (which runs
 * first alphabetically) leaving a usable `from` + file transport behind on the
 * shared application instance — so they passed in a full-suite run and failed
 * whenever the folder ran alone.
 *
 * `pin()` is idempotent: nested calls keep the ORIGINAL snapshot so a single
 * `restore()` still lands back on the as-installed values.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class MailerFixture
{
    // Const Properties
    // =========================================================================

    /**
     * The `from` address the fixture pins. Deliberately a `.test` TLD so a
     * misconfigured transport can never deliver anywhere real.
     *
     * Pinned as a bare string rather than the `[email => name]` array shape:
     * the array form is what breaks in the first place (a null display name
     * reaching `Symfony\Component\Mime\Address`), and `Mailer::$from`'s
     * docblock narrows `array` to `array<User>`, so the associative shape
     * doesn't type-check either. A plain address needs no display name.
     */
    public const FROM_EMAIL = 'tests@craftpulse.test';

    // Private Properties
    // =========================================================================

    /**
     * Snapshot of the mailer state taken by the first `pin()` call, or `null`
     * when the fixture isn't currently pinned.
     *
     * @var array{from: User|string|array|null, useFileTransport: bool}|null
     */
    private static ?array $_snapshot = null;

    // Public Methods
    // =========================================================================

    /**
     * Snapshots the application mailer's `from` + `useFileTransport` and
     * replaces them with a buffered transport and a valid sender.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function pin(): void
    {
        $mailer = self::mailer();

        self::$_snapshot ??= [
            'from' => $mailer->from,
            'useFileTransport' => $mailer->useFileTransport,
        ];

        $mailer->useFileTransport = true;
        $mailer->from = self::FROM_EMAIL;
    }

    /**
     * Restores whatever `pin()` snapshotted. A no-op when the fixture was
     * never pinned, so an unconditional `afterEach` call is safe.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function restore(): void
    {
        if (self::$_snapshot === null) {
            return;
        }

        $mailer = self::mailer();
        $mailer->from = self::$_snapshot['from'];
        $mailer->useFileTransport = self::$_snapshot['useFileTransport'];

        self::$_snapshot = null;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the application mailer narrowed to Craft's subclass, which is
     * what declares the `$from` property.
     *
     * @return Mailer
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function mailer(): Mailer
    {
        /** @var Mailer $mailer */
        $mailer = Craft::$app->getMailer();

        return $mailer;
    }
}
