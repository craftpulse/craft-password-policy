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
 * Class RetentionService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.1.0
 */
class SecurityService extends Component
{
    /** @var string|null the nonce */
    private ?string $_nonce = null;

    /**
     * Generate and return the CSP nonce for this request
     * @throws Exception
     */
    public function getNonce(): string
    {
        if ($this->_nonce === null) {
            $this->_nonce = Craft::$app->getSecurity()->generateRandomString(32);
        }

        return $this->_nonce;
    }

    /**
     * Apply Content Security Policy with nonce for indicator script
     * @throws Exception
     */
    public function applyCsp(): void
    {
        $nonce = $this->getNonce();
        $csp = "script-src 'self' 'unsafe-inline' 'nonce-{$nonce}'";

        Craft::$app->getResponse()->getHeaders()->add('Content-Security-Policy', $csp);
    }
}
