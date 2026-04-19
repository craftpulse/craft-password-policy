# Phase 3 — Advanced Validators

## Overview

Phase 3 adds five new password validators and the blocklist infrastructure. All are pure logic — no new database tables (blocklist table was created in Phase 1).

## Validators

### SequentialCharsValidator (Pro)

Detects 3+ ascending/descending sequential characters:
- **ASCII sequences**: `abc`, `xyz`, `321`
- **Keyboard rows**: `qwerty`, `asdf`, `zxcv` (forward and reversed)

### RepeatedCharsValidator (Pro)

Detects 3+ consecutive repeated characters: `aaa`, `111`, `!!!`. Uses the regex `/(.)\1{2,}/`.

### ContextualValidator (Pro)

Checks passwords against contextual data (case-insensitive substring match, minimum 3 chars):
- Username
- Email local part
- First/last name
- System name (`Craft::$app->getSystemName()`)
- Primary site domain (extracted hostname)

### CommonPasswordValidator (Pro)

Queries the `passwordpolicy_blocklist` table for case-insensitive matches. Uses a cached hash map via `Craft::$app->getCache()` for O(1) runtime lookups. Cache invalidated on any add/remove/seed operation.

### MinimumCharacterTypesValidator (Pro)

"X of 4 character types" mode. Counts how many of uppercase, lowercase, digit, symbol are present. Requires >= `minimumCharacterTypes`. Only active when `complexityMode = 'minimum'` — mutually exclusive with individual `cases`/`numbers`/`symbols` toggles.

## BlocklistService

Manages common and custom password blocklist entries:
- `seedCommonPasswords()` — Deletes all `source='common'` rows, re-inserts from `data/common-passwords.php`
- `addCustomWord()` — Lowercased, trimmed, deduped
- `removeCustomWord()` — By ID, `source='custom'` only
- `getCustomWords()` — Paginated for EditableTable UI
- `getCommonCount()` — For UI display
- `isWordBlocked()` — Returns source if found, null if not
- `clearCache()` — Invalidates cached word set

## BlocklistController (Console)

- `password-policy/blocklist/update` — Re-seeds common passwords from bundled file
- `password-policy/blocklist/import --file=path/to/words.txt` — Bulk import custom words
- `password-policy/blocklist/stats` — Count by source

## Complexity Modes

- `complexityMode = 'individual'` (default): Existing behavior — `cases`, `numbers`, `symbols` booleans
- `complexityMode = 'minimum'`: Requires `minimumCharacterTypes` of 4 types. Individual toggles ignored in UI

## Common Passwords Data File

`src/data/common-passwords.php` contains a representative subset for alpha testing. Will be expanded to 10,000 entries before stable release. This file is a seed source only — imported into DB on install/update, not read at runtime.

## Edition Gating

All new validators are gated on Pro edition + their respective toggle in `UserRules::defineRules()`.
