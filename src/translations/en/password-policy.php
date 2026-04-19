<?php
/**
 * Password policy plugin for Craft CMS
 *
 * English translation file.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

return [
    // General
    '{name} plugin loaded' => '{name} plugin loaded',

    // Settings — Configuration
    'Enable "Have I Been Pwned"' => 'Enable "Have I Been Pwned"',
    'HIBP Failure Mode' => 'HIBP Failure Mode',
    'Fail-open (accept password)' => 'Fail-open (accept password)',
    'Fail-closed (reject password)' => 'Fail-closed (reject password)',
    'Show password strength indicator' => 'Show password strength indicator',
    'Force change on first login' => 'Force change on first login',
    'Enable CSP Nonce' => 'Enable CSP Nonce',

    // Settings — Password Rules
    'Minimum password length' => 'Minimum password length',
    'Maximum password length' => 'Maximum password length',
    'Complexity mode' => 'Complexity mode',
    'Individual toggles' => 'Individual toggles',
    'Minimum character types' => 'Minimum character types',
    'Require numbers' => 'Require numbers',
    'Require mixed case' => 'Require mixed case',
    'Require symbols' => 'Require symbols',

    // Settings — Password Retention
    'Enable retention utilities' => 'Enable retention utilities',
    'Expiry period' => 'Expiry period',
    'Expiry reminder days' => 'Expiry reminder days',

    // Settings — Password History
    'Password history count' => 'Password history count',
    'History retention (days)' => 'History retention (days)',

    // Settings — Advanced Validators
    'Block sequential characters' => 'Block sequential characters',
    'Block repeated characters' => 'Block repeated characters',
    'Block contextual passwords' => 'Block contextual passwords',
    'Block common passwords' => 'Block common passwords',

    // Settings — Group Policies
    'Enable per-group policies' => 'Enable per-group policies',

    // Settings — Audit Logging
    'Enable audit logging' => 'Enable audit logging',
    'Audit log retention (days)' => 'Audit log retention (days)',
    'Admin alert email' => 'Admin alert email',

    // Edition gating
    'edition required.' => 'edition required.',
    'Upgrade to unlock this feature.' => 'Upgrade to unlock this feature.',

    // Validation messages
    'Password must contain at least {min} characters.' => 'Password must contain at least {min} characters.',
    'Password can maximum contain {max} characters.' => 'Password can maximum contain {max} characters.',
    'Your password must contain at least one of each of the following: ' => 'Your password must contain at least one of each of the following: ',
    'This password has been compromised in a data breach. Please choose another password.' => 'This password has been compromised in a data breach. Please choose another password.',
    'Unable to verify password against breach database. Please try again later.' => 'Unable to verify password against breach database. Please try again later.',
    'This password has been used recently. Please choose a different password.' => 'This password has been used recently. Please choose a different password.',
    'Password must not contain sequential characters (e.g., abc, 123, qwerty).' => 'Password must not contain sequential characters (e.g., abc, 123, qwerty).',
    'Password must not contain 3 or more repeated characters in a row.' => 'Password must not contain 3 or more repeated characters in a row.',
    'Password must not contain your name, username, email, or site name.' => 'Password must not contain your name, username, email, or site name.',
    'This password is too common. Please choose a more unique password.' => 'This password is too common. Please choose a more unique password.',
    'Password must contain at least {count} of 4 character types (uppercase, lowercase, number, symbol).' => 'Password must contain at least {count} of 4 character types (uppercase, lowercase, number, symbol).',

    // AJAX validation
    'At least {min} characters' => 'At least {min} characters',
    'No more than {max} characters' => 'No more than {max} characters',
    'Upper and lowercase letters' => 'Upper and lowercase letters',
    'At least one number' => 'At least one number',
    'At least one special character' => 'At least one special character',
    'At least {count} of 4 character types' => 'At least {count} of 4 character types',
    'No sequential characters' => 'No sequential characters',
    'No repeated characters' => 'No repeated characters',
    'Not a common password' => 'Not a common password',
    'Not found in breach database' => 'Not found in breach database',

    // Complexity patterns
    'a lowercase character, an uppercase character' => 'a lowercase character, an uppercase character',
    'a number' => 'a number',
    'a special character.' => 'a special character.',
    ' and ' => ' and ',

    // Settings validation
    'The minimum length can not be less than 6.' => 'The minimum length can not be less than 6.',
    'The minimum length must be less than or equal to the maximum length.' => 'The minimum length must be less than or equal to the maximum length.',
    'The selected expiry period is invalid.' => 'The selected expiry period is invalid.',

    // Permissions
    'Manage plugin settings.' => 'Manage plugin settings.',
    'Force reset passwords retention access.' => 'Force reset passwords retention access.',

    // Bulk action
    'Force Password Reset' => 'Force Password Reset',

    // Periods
    'Day(s)' => 'Day(s)',
    'Week(s)' => 'Week(s)',
    'Month(s)' => 'Month(s)',
    'Year(s)' => 'Year(s)',
];
