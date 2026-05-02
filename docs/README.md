# Password Policy — Documentation Index

A Craft CMS 5 plugin for enforcing secure password policies — minimum length, complexity, expiry, history, blocklist, breach detection, per-group policies, and Enterprise-grade audit logging. Three editions: Lite (free), Pro (paid), Enterprise (gated).

## Where to find things

| Looking for…                              | Go to                                                  |
|-------------------------------------------|--------------------------------------------------------|
| How to use a feature                      | [`user/features/`](./user/features/)                   |
| The events you can hook into              | [`user/reference/events.md`](./user/reference/events.md) |
| The database schema                       | [`user/reference/database-schema.md`](./user/reference/database-schema.md) |
| The AJAX validation endpoint              | [`user/reference/ajax-validate.md`](./user/reference/ajax-validate.md) |
| Deployment / cron / retention             | [`user/operations/gc-and-retention.md`](./user/operations/gc-and-retention.md) |
| What edition has what                     | [`user/editions.md`](./user/editions.md)               |
| Maintainers / AI agents                   | start with [`internal/handover.md`](./internal/handover.md) |

## Features (`user/features/`)

| File                                                                       | What it covers |
|----------------------------------------------------------------------------|----------------|
| [`audit-logging.md`](./user/features/audit-logging.md)                     | Enterprise audit-log service + event listeners + privacy guarantees. |
| [`force-reset.md`](./user/features/force-reset.md)                         | Pro session-invalidation + group-based force reset. |
| [`frontend-twig.md`](./user/features/frontend-twig.md)                     | Pro front-end Twig render builders, JS asset, strength engine A+B. |
| [`notifications.md`](./user/features/notifications.md)                     | Pro+ notification email infrastructure (template editor, queue job, expiry reminders). |
| [`password-history.md`](./user/features/password-history.md)               | Password-reuse prevention + history lifecycle. |
| [`per-group-policies.md`](./user/features/per-group-policies.md)           | Pro per-group named policies (CRUD, presets, tri-state overrides). |
| [`user-index.md`](./user/features/user-index.md)                           | Users-index integration (table attributes, condition rules, bulk actions). |
| [`validators.md`](./user/features/validators.md)                           | The seven validator classes (HIBP, sequential, repeated, contextual, blocklist, character types, history). |

## How the docs are organised

`docs/user/` is for end users and integrators — anything we'd publish on the Plugin Store or hand to a partner. Plain Markdown, no badges, no fancy tooling.

`docs/internal/` is for plugin maintainers and AI agents. It carries the handover doc, master plan, manual-test register, and a placeholder progress log that points at rotated phase logs in `internal/history/`. Closed phase plans (e.g. `phase-c2-build-plan.md`) also live in `history/` as frozen artifacts.

When a phase closes, sessions in `internal/progress.md` rotate into `internal/history/progress-phase-<id>.md` and the active progress log slims down to a small pointer. The current phase is recorded at the top of `internal/progress.md`.

## See also

- Plugin root [`README.md`](../README.md)
- [`CHANGELOG.md`](../CHANGELOG.md)
