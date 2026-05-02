<!-- craftcms-claude-skills v1.3.0 -->
# Claude Code project guide — craft-password-policy

@.claude/rules/coding-style.md
@.claude/rules/architecture.md
@.claude/rules/git-workflow.md
@.claude/rules/scaffolding.md
@.claude/rules/security.md
@.claude/rules/migrations.md
@.claude/rules/testing.md

This file orients fresh Claude sessions to the plugin's structure, conventions, and the docs hierarchy. Read this before opening anything in `docs/`.

## What this plugin is

`craftpulse/craft-password-policy` is a Craft CMS 5 plugin for enforcing secure password policies — minimum length, complexity, expiry, history, blocklist, breach detection (HIBP), per-group policies, and Enterprise-grade audit logging.

Three editions ship from a single 5.2.0 release: Lite (free, baseline policy enforcement + history), Pro (per-group policies, blocklist editor, notifications, front-end Twig surface, HIBP-on-login), Enterprise (audit logging + compliance dashboard + SIEM/webhooks). Nothing tags until Enterprise is built.

## Memory store

Durable rules for this project live in `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/`. **Read `MEMORY.md` first** — index of all `feedback_*.md` and `project_*.md` durable rules.

## Docs structure

- `docs/README.md` — orientation index (where to find things).
- `docs/internal/handover.md` — **read this first** for AI session handover. Single page covering: current state, what's next, playground state, commands.
- `docs/internal/plan.md` — master plan (§1 status, §2 tests, §3 backlog, §4 build order). Active work.
- `docs/internal/reference.md` — completed work, settled architecture decisions, source code inventory. Skip unless investigating prior context.
- `docs/internal/manual-tests.md` — manual test register (T0.x → T13.x).
- `docs/internal/progress.md` — current-phase session log. Older phases rotated to `internal/history/`.
- `docs/internal/ideas.md` — post-5.2.0 / unscoped concepts.
- `docs/internal/history/` — closed phase plans + rotated session logs.
- `docs/user/` — end-user / integrator-facing docs. Plugin Store reader audience.
- `docs/user/features/` — one file per shipped feature.
- `docs/user/operations/` — admin / deployment / cron docs.
- `docs/user/reference/` — API-style references (database schema, events, AJAX endpoints).
- `docs/user/editions.md` — Pro/Lite/Enterprise table + helpers + gating rules.

## Working with this project

- Plugin path: `/Users/michtio/dev/craft-plugins/v5/craft-password-policy`
- Playground: `/Users/michtio/dev/craft-plugin-playground/cms_v5`
- Playground URL: `https://plugin-playground-v5.ddev.site/admin`
- Playground admin login: `development@craftpulse.com` / `Letmein-Craftpulse1!`
- All commands via `ddev` shorthand. Never `php`/`composer`/`npm` on the host.
- All migrations via `ddev craft migrate/create <Name> --plugin=password-policy`. Never hand-pick filenames or timestamps.

## Conventions

PHPDocs on every class and public method (`@author CraftPulse`, `@since x.y.z`). Section headers `=========`. Non-negotiable.

For Twig conventions, load the `craft-twig-guidelines` skill. For PHP conventions, load `craft-php-guidelines`. For broader Craft 5 patterns, load `craftcms`.

No AI attribution in commits, code, or docs.

## Where to start

A fresh Claude session should:
1. Read `MEMORY.md` (durable rules).
2. Read `docs/internal/handover.md` (current state + read-order).
3. From handover, follow the read order — usually `internal/plan.md` § 1, then `internal/progress.md` tail.
4. Specific feature work? Read the relevant `docs/user/features/*.md`.

If you're a builder agent, the handover doc contains the brief.
