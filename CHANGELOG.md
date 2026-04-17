# Release Notes for Password Policy

## 5.1.1 - 2026-04-17
### Changed
- Symbols regex now accepts any non-alphanumeric character (hyphens, underscores, etc.) instead of a limited set [#46](https://github.com/craftpulse/craft-password-policy/issues/46)
- Console `force-reset-passwords` command now runs synchronously by default; use `--queue` to push to the queue instead
- Password expiry query now filters at the database level instead of hydrating all users into memory
- Replaced `switch` with `match` expression in `PasswordResetHelper`
- Applied coding conventions: section headers, `@author` on methods, `@throws` annotations, underscore-prefixed private members

### Fixed
- Fixed a critical security issue where `RetentionController` had CSRF disabled and allowed anonymous access, enabling unauthenticated mass password resets
- Fixed `RetentionController::afterAction()` blocking web requests by synchronously draining the entire queue
- Fixed admin account exclusion being hardcoded to user ID 1 instead of using the `admin` property
- Fixed `getCpNavItem()` null dereference when no user is authenticated
- Fixed static `$settings` property never being populated
- Fixed `SettingsController::actionSave()` running permission checks before `requirePostRequest()`
- Fixed `SettingsModel::defineRules()` not calling `parent::defineRules()`
- Fixed console `force-reset-passwords` returning `ExitCode::OK` when retention features are disabled
- Fixed double `Craft::t()` nesting in `UserRules` that broke non-English translations
- Fixed `SecurityService` class docblock saying "RetentionService"
- Removed dead `$users` property from `PasswordResetJob`
- Removed dead `$vacancyId` parameter from `RetentionController::getFailureResponse()`
- Removed no-op `EVENT_AFTER_SAVE_PLUGIN_SETTINGS` handler
- Replaced redundant ternary with `isNotEmpty()` in `PasswordService::pwned()`
- Fixed `PasswordPolicyAsset` using property access instead of getter for view
- Fixed `$queue` property type from `mixed|object|null` to `?object`

## 5.1.0 - 2025-10-28
### Added
- Added optional CSP (Content Security Policy) nonce support for the password indicator script [#39](https://github.com/craftpulse/craft-password-policy/issues/39)
- Added `SecurityService` to generate and manage CSP nonces per request
- Added `cspNonce` configuration option to enable CSP nonce generation

### Changed
- Made sure that the rules thrown by Password Policy all show at once, rather than one by one.

### Fixed
- Fixed an issue where the native Craft errors would still display when password policy was active [#40](https://github.com/craftpulse/craft-password-policy/issues/40)
- Fixed an issue where the retention feature never actually got processed [#41](https://github.com/craftpulse/craft-password-policy/issues/41)

## 5.0.3 - 2025-01-07
### Changed
- Added services to a service trait

### Fixed
- Fixed a bug that could occur if the max length wasn't set, passwords always said "could not contain more than 0 characters".
- Removed the "playground" from the settings to test the strength indicator, this was only meant for development.
- Fixed an issue where the pwned option would always return that the password was compromised.
- Fixed the issue where the assets would throw an error on the front-end, not finding the manifest path. (Thanks to Andrew Welch) [#34](https://github.com/craftpulse/craft-password-policy/issues/34)

## 5.0.2.1 - 2024-12-19
### Fixed
- Fixed `Failed to instantiate component or class` on the assetbundle [Thanks niektenhoopen](https://github.com/craftpulse/craft-password-policy/pull/33)

## 5.0.2 - 2024-12-16
### Fixed
- Fixed native type class constant as those are only allowed from PHP8.3+

## 5.0.1.1 - 2024-12-16
### Fixed
- More ECS fixes after PHPStan fixes

## 5.0.1 - 2024-12-16
### Fixed
- ECS Style fixes
- Fixed PHP Stan Errors

## 5.0.0 - 2024-12-15
### Added
- Added a "Have I been pwned" validator [#29](https://github.com/craftpulse/craft-password-policy/issues/29)
- Added "Have I been pwned" through k-anonymity
- Password Retention feature to determine on which time interval passwords should expire
- Added the `craft password-policy/retention/force-reset-passwords` CLI command
- Added the "Force Reset Passwords" Retention Utility

### Changed
- Refactored the password strength indicator, now using vanilla JS and TailwindCSS
- Refactored all the validation rules
