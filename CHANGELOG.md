# Release Notes for Password Policy

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
