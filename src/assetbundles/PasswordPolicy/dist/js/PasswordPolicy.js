/**
 * Password Policy plugin for Craft CMS
 *
 * Password Policy JS
 *
 * @author    CraftPulse
 * @copyright Copyright (c) 2024 CraftPulse
 * @link      https://craftpulse.com
 * @package   PasswordPolicy
 * @since     1.0.0
 */

var newPasswordField = $('#newPassword');

if (newPasswordField.length > 0 && passwordpolicy.showStrengthIndicator) {
    // Append the progress bar
    newPasswordField.parent().append('<div class="password-policy-bar">');

    // Add a listener to show password strength
    newPasswordField.on('keyup', function (e) {
        var password = $(this).val();
        var bar = $('.password-policy-bar');
        bar.removeClass();
        bar.addClass('password-policy-bar');

        if (password) {
            var details = zxcvbn(password);
            bar.addClass('strength-' + details.score);
        }
    });
}
