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
    'Password Policy' => 'Passord Policy',

    // Settings
    'Minimum password length' => 'Longueur minimale du mot de passe',
    'Require a minimum password length' => 'Exiger une longueur minimale de mot de passe',
    'Maximum password length' => 'Longueur maximale du mot de passe',
    'Require a maximum password length.' => 'Exiger une longueur maximale du mot de passe.',
    'Cases' => 'Cases',
    'Require both upper-case and lower-case letters.' => 'Requiert lettres en base et haute case.',
    'Numbers' => 'Chiffres',
    'Require one or more numerical digits.' => 'Nécessite un ou plusieurs chiffres numériques.',
    'Symbols' => 'Symboles',
    'Require special characters like @, #, $.' => 'Exiger des caractères spéciaux tels que @, #, $.',
    'Check Pwned database' => 'Vérifier la base de données Pwned',
    'Check the [Pwned Passwords](https://haveibeenpwned.com/Passwords) database.' => 'Vérifier la base de données Pwned [Pwned Passwords](https://haveibeenpwned.com/Passwords).',
    'Show strength indicator' => 'Afficher l\'indicateur de force',
    'Show a password strength indicator.' => 'Afficher un indicateur de force du mot de passe.',

    // Errors
    'Password needs to be at least {min} characters.' => 'Le mot de passe doit contenir au moins {min} caractères.',
    'Password needs to be less than {max} characters.' => 'Le mot de passe doit contenir moins de {max} caractères.',
    'Password needs to be both upper- and lower-case.' => 'Le mot de passe doit être en majuscules et en minuscules.',
    'Password needs to contain at least 1 numeric character.' => 'Le mot de passe doit contenir au moins 1 caractère numérique.',
    'Password needs to contain at least 1 symbol like @, #, $' => 'Le mot de passe doit contenir au moins 1 symbole comme @, #, $',
    'Password has been Pwned (https://haveibeenpwned.com/Passwords).' => 'Le mot de passe a été Pwned (https://haveibeenpwned.com/Passwords).',
];
