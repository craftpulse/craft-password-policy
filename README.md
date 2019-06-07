![Icon](./src/icon.svg)

[![Latest Version](https://img.shields.io/github/release/riasvdv/craft-password-policy.svg?style=flat-square)](https://github.com/riasvdv/craft-password-policy/releases)
[![Quality Score](https://img.shields.io/scrutinizer/g/riasvdv/craft-password-policy.svg?style=flat-square)](https://scrutinizer-ci.com/g/riasvdv/craft-password-policy)
[![StyleCI](https://styleci.io/repos/128541682/shield)](https://styleci.io/repos/128541682)
[![Total Downloads](https://img.shields.io/packagist/dt/rias/craft-password-policy.svg?style=flat-square)](https://packagist.org/packages/rias/craft-password-policy)

# Password Policy plugin for Craft CMS 3

Enforce a password policy on your users. This plugin can also check the [Have I been Pwned database](https://haveibeenpwned.com/Passwords) to make sure users use a password that is secure.

Policy Errors:
![Screenshot](resources/img/screenshot.png)

Password Strength Indicator
![Screenshot](resources/img/screenshot3.png)

## Support Open Source. Buy beer.

This plugin is licensed under a MIT license, which means that it's completely free open source software, and you can use it for whatever and however you wish. If you're using it and want to support the development, buy me a beer over at Beerpay!

[![Beerpay](https://beerpay.io/riasvdv/craft-password-policy/badge.svg?style=beer-square)](https://beerpay.io/riasvdv/craft-password-policy)

## Requirements

This plugin requires Craft CMS 3.0.0.

## Installation

You can install this plugin through the plugin store.

## Configuration

You can configure this plugin by adding a `config/password-policy.php` file:

```php
<?php

return [
    // Minimum password length
    "minLength" => 16,
    
    // Maximum password length
    "maxLength" => 160,
    
    // Force users to use different cases
    "cases" => false,
    
    // Require at least 1 number
    "numbers" => false,
    
    // Require at least one symbol
    "symbols" => false,
    
    // Check the Have I been Pwned database
    "checkPwned" => true,
    
    // Show a password strength indicator
    "showStrengthIndicator" => true,
];
``` 

Or through the plugin settings

![Screenshot](resources/img/screenshot2.png)

Brought to you by [Rias](https://rias.be)
