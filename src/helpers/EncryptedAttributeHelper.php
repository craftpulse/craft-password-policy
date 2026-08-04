<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

declare(strict_types=1);

namespace craftpulse\passwordpolicy\helpers;

use Craft;
use Throwable;

/**
 * Class EncryptedAttributeHelper
 *
 * The plugin's one encrypt-at-rest boundary for credential columns. Used
 * by {@see \craftpulse\passwordpolicy\models\WebhookEndpointModel} for
 * its two HMAC signing secrets and by
 * {@see \craftpulse\passwordpolicy\models\SiemForwarderModel} for an HTTP
 * forwarder's auth token.
 *
 * The envelope is Craft's `Security::encryptByKey()` with no key
 * argument, which uses the install's `securityKey` from
 * `config/general.php`. Don't introduce a per-plugin key.
 *
 * The base64 wrap is needed because `encryptByKey()` returns raw binary
 * bytes (HKDF + AES + HMAC envelope). MySQL `text` columns are utf8mb4 by
 * default and reject sequences that aren't valid UTF-8; wrapping keeps the
 * column ASCII-clean across MySQL, PostgreSQL, and SQLite.
 *
 * Read failures return null rather than throwing. A corrupted ciphertext
 * or a rotated `securityKey` must degrade the affected destination
 * visibly, not crash a queue worker mid-sweep — both consuming services
 * treat a null credential as "unusable" and refuse to send.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class EncryptedAttributeHelper
{
    // Static Methods
    // =========================================================================

    /**
     * Attempts to decrypt a base64-wrapped ciphertext blob. Returns null on
     * any failure, logging a warning that names `$label` so the operator can
     * tell which credential went unreadable without the value appearing in
     * the log.
     *
     * @param string $cipher base64-encoded ciphertext straight from the DB
     * @param string $label human-readable name of the credential, used in
     *     the warning only (e.g. `'webhook endpoint secret'`)
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function decryptOrNull(string $cipher, string $label): ?string
    {
        if ($cipher === '') {
            return null;
        }

        $raw = base64_decode($cipher, true);

        if ($raw === false) {
            Craft::warning(
                'The stored ' . $label . ' is not valid base64; cannot decrypt.',
                'password-policy',
            );

            return null;
        }

        try {
            $decrypted = Craft::$app->getSecurity()->decryptByKey($raw);
        } catch (Throwable $e) {
            Craft::warning(
                'Failed to decrypt the stored ' . $label . ': ' . $e->getMessage(),
                'password-policy',
            );

            return null;
        }

        return $decrypted !== false ? $decrypted : null;
    }

    /**
     * Encrypts plaintext and wraps the binary output in base64 so it stores
     * cleanly in a utf8mb4 `text` column. Pairs with
     * {@see decryptOrNull()} on the read side.
     *
     * @param string $plaintext
     * @return string base64-encoded ciphertext suitable for DB storage
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function encrypt(#[\SensitiveParameter] string $plaintext): string
    {
        return base64_encode(
            Craft::$app->getSecurity()->encryptByKey($plaintext),
        );
    }
}
