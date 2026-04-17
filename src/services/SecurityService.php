<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\base\Component;
use yii\base\Exception;

/**
 * Class SecurityService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.1.0
 */
class SecurityService extends Component
{
    // Private Properties
    // =========================================================================

    /**
     * @var string|null the nonce
     */
    private ?string $_nonce = null;

    // Public Methods
    // =========================================================================

    /**
     * Generates and returns the CSP nonce for this request.
     *
     * @return string
     *
     * @throws Exception
     *
     * @author CraftPulse
     */
    public function getNonce(): string
    {
        if ($this->_nonce === null) {
            $this->_nonce = Craft::$app->getSecurity()->generateRandomString(32);
        }

        return $this->_nonce;
    }

    /**
     * Applies a Content Security Policy header with nonce for the indicator script.
     *
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     */
    public function applyCsp(): void
    {
        $nonce = $this->getNonce();
        $csp = "script-src 'self' 'unsafe-inline' 'nonce-{$nonce}'";

        Craft::$app->getResponse()->getHeaders()->add('Content-Security-Policy', $csp);
    }
}
