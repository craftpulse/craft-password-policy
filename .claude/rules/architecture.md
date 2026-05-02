<!-- craftcms-claude-skills -->
# Architecture — craftpulse/craft-password-policy

The plugin layers components per Craft 5 idiom. Load the `craftcms` skill for the broader patterns; this file captures project-specific architecture.

## Directory layout

```
src/
├── PasswordPolicy.php              # entry point — init(), event handlers, log helper
├── assetbundles/                   # CP + front-end JS asset bundles
├── console/controllers/            # CLI controllers (gc, audit, blocklist, notification)
├── controllers/                    # CP web controllers
├── controllers/front/              # front-end web controllers (PasswordChange, etc.)
├── data/                           # static data (common-passwords.php, EmailDefaults.php)
├── elements/                       # condition rules + element actions
├── events/                         # custom event classes
├── jobs/                           # queue jobs
├── migrations/                     # Install.php + dated migrations
├── models/                         # SettingsModel, PolicyModel, GroupPolicyModel, NotificationTemplateModel
├── records/                        # ActiveRecord classes
├── records/                        # ActiveRecord classes for tables
├── rules/                          # User element rule definitions
├── services/                       # business logic, registered via ServicesTrait
├── templates/                      # CP Twig templates
├── twig/tags/                      # fluent render builder Tag classes (P1.12)
├── utilities/                      # CP utility pages (RetentionUtility, etc.)
├── validators/                     # password validators
└── variables/                      # PasswordPolicyVariable.php
```

## Layering rules

- **Services own business logic.** Controllers wire HTTP/CLI to services. Models own validation. Records map to tables.
- **Services registered in `ServicesTrait`** — getters with PHPDoc return types so IDEs can navigate.
- **Events fired AFTER successful state change.** Use `yii\base\Event::trigger()` from the layer that performed the change (usually a service).
- **Project config writes wrapped in `muteEvents` try/finally.** No project-config-driven event re-entry.
- **HIBP-on-login** uses `User::EVENT_BEFORE_AUTHENTICATE` — only Craft 5 hook with synchronous plaintext-in-scope access. Privacy guards in code comments at the listener.
- **Front-end controllers** in `controllers/front/` (lowercase to match namespace on case-sensitive filesystems). `$allowAnonymous = false` for logged-in flows; `['save']` for token-based reset.

## Edition gating

- **Lite** ships baseline policy enforcement (length, complexity, expiry, history at count=0, blocklist toggle).
- **Pro** adds per-group policies, blocklist editor, notifications, front-end Twig surface, HIBP-on-login, zxcvbn-php opt-in, named-policy CRUD.
- **Enterprise** adds audit logging, compliance dashboard, SIEM/webhooks (Phase 10–12, not yet built).

Gating idiom:

- **CP**: visible-but-disabled with "Pro edition required" badge — keeps upgrade path discoverable.
- **Front-end builders**: graceful degradation. Lite → global resolution; Pro → per-group via `PolicyResolverService`. No 403s on the front-end.
- **HIBP-on-login**: Pro-only listener registration. Lite installs simply don't fire it.
- **`SettingsController::actionSave`** unconditionally `unset()` Pro/Enterprise keys for sub-edition saves — defense-in-depth even though UI doesn't render them.

## Variable handle

`craft.passwordpolicy.*` AND `craft.passwordPolicy.*` both work. Both registered. Lowercase exists for 5.1.1 backward compat; camelCase is the canonical form going forward.

## Asset bundles

- `PasswordPolicyAsset` — CP-side, registered on every CP request via `View::EVENT_BEFORE_RENDER_PAGE_TEMPLATE`. Sets `window.passwordpolicy.showStrengthIndicator` flag and registers the Vite-built strength indicator JS.
- `PasswordPolicyClientAsset` — front-end consumer asset. Auto-registered when any builder is called with an interactivity flag (`liveValidation`, `toggleVisibility`, or `submitGate`). Consumer site doesn't need Vite or a build step.

## Storage idioms

- **Per-(entity, site) editable content**: one row per `(key, siteId)` with JSON `content` column (Craft 5 elements pattern). Used for `passwordpolicy_notification_templates`. Not Craft-4-style relational columns.
- **Datetime columns** from ActiveRecord come back as raw strings — hydrate via `DateTimeHelper::toDateTime()` in `Model::fromRecord()`.
