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
 * Password Policy nb Translation.
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
    'Password Policy' => 'Passordpolicy',

    // Settings
    'Minimum password length'                                                     => 'Minimum passordlengde',
    'Require a minimum password length'                                           => 'Krev minimum passordlengde',
    'Maximum password length'                                                     => 'Maksimum passordlengde',
    'Require a maximum password length.'                                          => 'Krev maksimum passordlengde',
    'Cases'                                                                       => 'Store/Små Bokstaver',
    'Require both upper-case and lower-case letters.'                             => 'Krev både store og små bokstaver.',
    'Numbers'                                                                     => 'Nummer',
    'Require one or more numerical digits.'                                       => 'Krev ett eller flere numeriske tegn.',
    'Symbols'                                                                     => 'Symboler',
    'Require special characters like @, #, $.'                                    => 'Krev spesielle tegn som  @, #, $.',
    'Check Pwned database'                                                        => 'Sjekk Pwned database',
    'Check the [Pwned Passwords](https://haveibeenpwned.com/Passwords) database.' => 'Sjekk [Pwned Passwords](https://haveibeenpwned.com/Passwords) databasen.',
    'Show strength indicator'                                                     => 'Vis passordstyrkeindikator',
    'Show a password strength indicator.'                                         => 'Vis en indikator for passordstyrke.',

    // Errors
    'Password needs to be at least {min} characters.'                 => 'Passordet må være minst {min} tegn.',
    'Password needs to be less than {max} characters.'                => 'Passordet må være maks {max} tegn.',
    'Password needs to be both upper- and lower-case.'                => 'Passordet må inneholde både store og små bokstaver.',
    'Password needs to contain at least 1 numeric character.'         => 'Passordet må inneholde minst 1 numerisk tegn.',
    'Password needs to contain at least 1 symbol like @, #, $'        => 'Passordet må inneholde minst 1 symbol som @, #, $',
    'Password has been Pwned (https://haveibeenpwned.com/Passwords).' => 'Passordet er i Pwned databasen (https://haveibeenpwned.com/Passwords).',
];
