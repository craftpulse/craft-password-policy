![Icon](./src/icon.svg)

[![Latest Version](https://img.shields.io/github/release/rias500/craft-password-policy.svg?style=flat-square)](https://github.com/rias500/craft-password-policy/releases)
[![Quality Score](https://img.shields.io/scrutinizer/g/rias500/craft-password-policy.svg?style=flat-square)](https://scrutinizer-ci.com/g/rias500/craft-password-policy)
[![StyleCI](https://styleci.io/repos/128541682/shield)](https://styleci.io/repos/128541682)
[![Total Downloads](https://img.shields.io/packagist/dt/rias/craft-password-policy.svg?style=flat-square)](https://packagist.org/packages/rias/craft-password-policy)

# Password Policy plugin for Craft CMS 3

Enforce a password policy on your users. This plugin can also check the [Have I been Pwned database](https://haveibeenpwned.com/Passwords) to make sure users use a password that is secure.

![Screenshot](resources/img/screenshot.png)

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
];
``` 

Or through the plugin settings

![Screenshot](resources/img/screenshot2.png)

## Password Policy Roadmap

Upcoming features:

* Showing a password strength indicator.

Brought to you by [Rias](https://rias.be)
