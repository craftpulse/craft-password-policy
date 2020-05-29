<?php
/**
 * Password Policy plugin for Craft CMS 3.x.
 *
 * Enforce stronger passwords on your users.
 *
 * @link      https://percipio.london
 *
 * @copyright Copyright (c) 2020 Percipio Global Ltd.
 */

/**
 * Password Policy config.php.
 *
 * This file exists only as a template for the Password Policy settings.
 * It does nothing on its own.
 *
 * Don't edit this file, instead copy it to 'craft/config' as 'password-policy.php'
 * and make your changes there to override default settings.
 *
 * Once copied to 'craft/config', this file will be multi-environment aware as
 * well, so you can have different settings groups for each environment, just as
 * you do for 'general.php'
 */

return [
    'minLength'             => 16,
    'maxLength'             => 160,
    'cases'                 => false,
    'numbers'               => false,
    'symbols'               => false,
    'checkPwned'            => true,
    'showStrengthIndicator' => true,
];
