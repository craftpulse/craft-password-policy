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
 * Password Policy nl Translation.
 *
 * Returns an array with the string to be translated (as passed to `Craft::t('password-policy', '...')`) as
 * the key, and the translation as the value.
 *
 * http://www.yiiframework.com/doc-2.0/guide-tutorial-i18n.html
 *
 * @author    Percipio Global Ltd.
 *
 * @since     1.0.0
 */
return [
    // Plugin name
    'Password Policy' => 'Wachtwoord Policy',

    // Settings
    'Minimum password length'                                                     => 'Minimum lengte',
    'Require a minimum password length'                                           => 'Vereis een minimum wachtwoordlengte.',
    'Maximum password length'                                                     => 'Maximum lengte',
    'Require a maximum password length.'                                          => 'Vereis een maximum wachtwoordlengte.',
    'Cases'                                                                       => 'Hoofdletters/Kleine Letters',
    'Require both upper-case and lower-case letters.'                             => 'Vereis zowel hoofd- als kleine letters.',
    'Numbers'                                                                     => 'Nummers',
    'Require one or more numerical digits.'                                       => 'Vereis minstens 1 numeriek karakter.',
    'Symbols'                                                                     => 'Symbolen',
    'Require special characters like @, #, $.'                                    => 'Vereis speciale karakters zoals @, #, $.',
    'Check Pwned database'                                                        => 'Controleer de Pwned database',
    'Check the [Pwned Passwords](https://haveibeenpwned.com/Passwords) database.' => 'Controleer de [Pwned Passwords](https://haveibeenpwned.com/Passwords) database.',
    'Show strength indicator'                                                     => 'Wachtwoord sterkte',
    'Show a password strength indicator.'                                         => 'Toon een gekleurde balk om de wachtwoord sterkte aan te duiden.',

    // Errors
    'Password needs to be at least {min} characters.'                 => 'Wachtwoord moet minstens {min} tekens bevatten.',
    'Password needs to be less than {max} characters.'                => 'Wachtwoord mag maximum {max} tekens bevatten.',
    'Password needs to be both upper- and lower-case.'                => 'Wachtwoord moet zowel hoofdletters als kleine letters bevatten.',
    'Password needs to contain at least 1 numeric character.'         => 'Wachtwoord moet minstens 1 nummer bevatten.',
    'Password needs to contain at least 1 symbol like @, #, $'        => 'Wachtwoord moet minstens 1 symbool zoals @, #, $ bevatten.',
    'Password has been Pwned (https://haveibeenpwned.com/Passwords).' => 'Wachtwoord is gekend (https://haveibeenpwned.com/Passwords).',
];
