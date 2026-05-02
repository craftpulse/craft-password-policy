<!-- craftcms-claude-skills -->
# Coding style — craftpulse/craft-password-policy

Conventions enforced via ECS + PHPStan + manual review. Load the `craft-php-guidelines` skill for full PHP standards; this file captures project-specific deltas.

## Mandatory

- **PHPDocs on every class and public method.** `@author CraftPulse` + `@since x.y.z` on classes and on public methods (the version is the version that introduced THIS method, not the class).
- **Section headers** with `=========` separators on every class. Group: `Constants`, `Static Properties`, `Static Methods`, `Public Properties`, `Private Properties`, `Public Methods`, `Private Methods`. Headers use `// Section name` + `// =========================================================================`.
- **`@deprecated since x.y.z`** is appropriate ONLY for legacy public API being renamed (e.g. `pwned` → `hibp`). Never deprecate code that was added in the same unreleased version — delete dead code instead.
- **`#[\SensitiveParameter]`** on every plaintext password argument. PHP omits the value from stack traces.

## Tooling

```bash
ddev composer check-cs       # ECS — must pass before commit
ddev composer fix-cs         # ECS auto-fix
ddev composer phpstan        # PHPStan — must pass before commit (1G memory)
```

ECS may break on the host when the playground vendor was installed against PHP 8.4 vs DDEV's PHP 8.3. Recompile vendor inside DDEV: `ddev exec --dir <plugin-vendor-path> composer update`.

## Conventions inherited from skills + memory

- Multi-line `Craft::t()` calls preferred over single-line — easier to scan in diffs.
- Don't inline private methods without reason (preserves encapsulation + named intent).
- Short nullable notation: `?string`, never `string|null`.
- Strict types: declare in new files; don't add `declare(strict_types=1)` to existing files in unrelated changes.
- Use `craft\helpers\DateTimeHelper::toDateTime()` to hydrate ActiveRecord datetime columns into `?DateTime` properties — direct assignment throws.
- `UserQuery::beforePrepare()` does NOT select `lastPasswordChangeDate` — direct DB scalar query against `Table::USERS` for that column.

## Naming

- Services end in `Service` — `PasswordService`, `BlocklistService`.
- Records end in `Record`.
- Models end in `Model`.
- Events end in `Event` — extend `yii\base\Event` or a Craft event class.
- Jobs end in `Job`. Queue jobs extend `\craft\queue\BaseJob` or `\craft\queue\BaseBatchedJob`.
- Validators end in `Validator`.
- Controllers end in `Controller`.
- Enums in `src/enums/`.
- Variable handle is `passwordpolicy` (lowercase, 5.1.x compat) AND `passwordPolicy` (camelCase, modern). Both registered.
