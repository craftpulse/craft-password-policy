<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\twig\tags;

use Craft;
use craft\helpers\Html;

/**
 * Class PasswordChangeFormTag
 *
 * Renders a `<form>` for a logged-in user to change their password.
 * Three fields: current password (required), new password (validated), confirm.
 * POSTs to `password-policy/front/password-change/save`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordChangeFormTag extends BaseTag
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
            'class' => 'pp-form pp-change-form',
            'novalidate' => true,
        ], (array)($this->config['formAttrs'] ?? []));

        $submitAttrs = array_merge([
            'type' => 'submit',
            'class' => 'pp-submit',
            'id' => 'pp-change-submit',
        ], (array)($this->config['submitButtonAttrs'] ?? []));

        $submitLabel = (string)($this->config['submitLabel'] ?? Craft::t('app', 'Update password'));

        $output = '<form' . $this->_renderAttrs($formAttrs) . '>';
        $output .= Html::hiddenInput('action', 'password-policy/front/password-change/save');
        $output .= Html::csrfInput();

        if (!empty($this->config['successRedirect'])) {
            $output .= Html::hiddenInput(
                'redirect',
                Craft::$app->getSecurity()->hashData((string)$this->config['successRedirect']),
            );
        }

        // Current password
        $currentField = new PasswordFieldTag([
            'name' => 'currentPassword',
            'id' => 'pp-current-password',
            'autocomplete' => 'current-password',
            'inputAttrs' => ['required' => true, 'class' => 'pp-input'],
            'toggleVisibility' => true,
            'liveValidation' => false,
        ]);
        $output .= '<label for="pp-current-password" class="pp-label">'
            . Html::encode(Craft::t('password-policy', 'Current password'))
            . '</label>';
        $output .= (string)$currentField;

        // New password — full live validation
        $newField = new PasswordFieldTag([
            'name' => 'newPassword',
            'id' => 'pp-new-password',
            'autocomplete' => 'new-password',
            'inputAttrs' => ['required' => true, 'class' => 'pp-input'],
            'toggleVisibility' => true,
            'liveValidation' => true,
            'submitGate' => '#' . $submitAttrs['id'],
        ]);
        $output .= '<label for="pp-new-password" class="pp-label">'
            . Html::encode(Craft::t('password-policy', 'New password'))
            . '</label>';
        $output .= (string)$newField;

        // Confirm
        $confirmField = new PasswordFieldTag([
            'name' => 'newPasswordConfirm',
            'id' => 'pp-new-password-confirm',
            'autocomplete' => 'new-password',
            'inputAttrs' => ['required' => true, 'class' => 'pp-input'],
            'toggleVisibility' => true,
            'liveValidation' => false,
        ]);
        $output .= '<label for="pp-new-password-confirm" class="pp-label">'
            . Html::encode(Craft::t('password-policy', 'Confirm new password'))
            . '</label>';
        $output .= (string)$confirmField;

        $output .= '<button' . $this->_renderAttrs($submitAttrs) . '>' . Html::encode($submitLabel) . '</button>';

        $output .= '</form>';

        return $output;
    }
}
