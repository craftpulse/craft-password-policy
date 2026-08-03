<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\twig\tags;

use Craft;
use craft\helpers\Html;

/**
 * Class LoginFormTag
 *
 * Renders a complete `<form>` POSTing to Craft's `users/login` action.
 * Includes username/email + password + remember-me + redirect + CSRF.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class LoginFormTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function formAttrs(array $attrs): self
    {
        $this->config['formAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function loginNameAttrs(array $attrs): self
    {
        $this->config['loginNameAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function passwordAttrs(array $attrs): self
    {
        $this->config['passwordAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function submitButtonAttrs(array $attrs): self
    {
        $this->config['submitButtonAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param string $label
     * @return $this
     */
    public function submitLabel(string $label): self
    {
        $this->config['submitLabel'] = $label;
        return $this;
    }

    /**
     * @param string $url
     * @return $this
     */
    public function successRedirect(string $url): self
    {
        $this->config['successRedirect'] = $url;
        return $this;
    }

    /**
     * @param bool $on
     * @return $this
     */
    public function rememberMe(bool $on): self
    {
        $this->config['rememberMe'] = $on;
        return $this;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _renderHtml(): string
    {
        $formAttrs = array_merge([
            'method' => 'post',
            'action' => '',
            'class' => 'pp-form pp-login-form',
            'novalidate' => true,
        ], (array)($this->config['formAttrs'] ?? []));

        $loginNameAttrs = array_merge([
            'type' => 'text',
            'name' => 'loginName',
            'id' => 'loginName',
            'autocomplete' => 'username',
            'required' => true,
            'class' => 'pp-input',
        ], (array)($this->config['loginNameAttrs'] ?? []));

        $passwordField = new PasswordFieldTag([
            'name' => 'password',
            'id' => 'pp-login-password',
            'autocomplete' => 'current-password',
            'inputAttrs' => array_merge([
                'required' => true,
                'class' => 'pp-input',
            ], (array)($this->config['passwordAttrs'] ?? [])),
            'toggleVisibility' => true,
            'liveValidation' => false,
        ]);

        $submitAttrs = array_merge([
            'type' => 'submit',
            'class' => 'pp-submit',
        ], (array)($this->config['submitButtonAttrs'] ?? []));

        $submitLabel = (string)($this->config['submitLabel'] ?? Craft::t('app', 'Login'));
        $successRedirect = $this->config['successRedirect'] ?? null;
        $rememberMe = (bool)($this->config['rememberMe'] ?? true);

        $output = '<form' . $this->_renderAttrs($formAttrs) . '>';
        $output .= Html::hiddenInput('action', 'users/login');
        $output .= Html::csrfInput();

        if ($successRedirect !== null) {
            $output .= Html::hiddenInput('redirect', Craft::$app->getSecurity()->hashData($successRedirect));
        }

        $output .= '<label for="loginName" class="pp-label">'
            . Html::encode(Craft::t('app', 'Username or email'))
            . '</label>';
        $output .= '<input' . $this->_renderAttrs($loginNameAttrs) . '>';

        $output .= '<label for="pp-login-password" class="pp-label">'
            . Html::encode(Craft::t('app', 'Password'))
            . '</label>';
        $output .= (string)$passwordField;


        if ($rememberMe) {
            $output .= '<label class="pp-checkbox">'
                . '<input type="checkbox" name="rememberMe" value="1"> '
                . Html::encode(Craft::t('app', 'Keep me signed in'))
                . '</label>';
        }

        $output .= '<button' . $this->_renderAttrs($submitAttrs) . '>' . Html::encode($submitLabel) . '</button>';

        $output .= '</form>';

        return $output;
    }
}
