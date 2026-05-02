<!-- craftcms-claude-skills -->
# Scaffolding — craftpulse/craft-password-policy

Generators always run through DDEV. Never `php`/`composer`/`npm` on the host (project-level `.claude/settings.json` enforces this).

## Common commands

```bash
ddev craft make                                      # Craft's interactive scaffolder
ddev craft migrate/create <Name> --plugin=password-policy   # ONLY way to author a migration
ddev craft migrate/up --plugin=password-policy        # Apply pending migrations
ddev craft project-config/get plugins.password-policy.settings.edition
ddev craft project-config/set plugins.password-policy.settings.<key> <value>
ddev craft up                                         # Migrations + project config apply
ddev craft plugin/install password-policy             # First-time install
ddev craft plugin/uninstall password-policy           # Tears down all 6 tables (reverse FK order)
ddev composer dump-autoload                           # After adding a new class
ddev composer require <package>                       # Requires explicit user approval
```

## When to add what

- **New service** → file in `src/services/`, register in `src/services/ServicesTrait.php` with a typed getter. PHPDoc `@author CraftPulse` + `@since x.y.z`.
- **New event** → file in `src/events/` extending `yii\base\Event` (or a Craft event class). PHPDoc with `@event` markup. Add a row to `docs/user/reference/events.md` in the same commit (events drift from documentation otherwise).
- **New permission** → register via `UserPermissions::EVENT_REGISTER_PERMISSIONS` in `src/PasswordPolicy.php`. Naming: `pp:<area>-<action>` (e.g. `pp:blocklist-manage`, `pp:notification-templates-manage`).
- **New CP subnav** → `getCpNavItem()` in `src/PasswordPolicy.php`. Gate on edition + permission.
- **New CP route** → URL rules registered in `_registerCpUrlRules()` (`UrlManager::EVENT_REGISTER_CP_URL_RULES`).
- **New front-end route** → URL rules in `_registerSiteUrlRules()` if exists, otherwise add via `UrlManager::EVENT_REGISTER_SITE_URL_RULES`.
- **New Twig variable method** → method on `src/variables/PasswordPolicyVariable.php`. Both `passwordpolicy` and `passwordPolicy` handles get it.
- **New Twig render builder** → Tag class in `src/twig/tags/` extending `BaseTag`. Implement `_renderHtml(): string`; `BaseTag::render()` wraps in `\Twig\Markup`. Add a wrapper method on `PasswordPolicyVariable.php` that returns the Tag instance.
- **New validator** → `src/validators/`, extends `craft\base\Element` validator pattern. Wire into `UserRules::defineRules()` if it should run on User saves.
- **New queue job** → `src/jobs/`, extends `\craft\queue\BaseJob` or `BaseBatchedJob`. For batched: override `defaultDescription()`, NOT `getDescription()` (final on BaseBatchedJob).

## Composer dep approval

Adding `composer require` for a runtime dep needs explicit user approval. Plugin selection is a planning-phase decision — fewer plugins / fewer deps is better. Approved deps are recorded in `docs/internal/plan.md` § 1 status block.
