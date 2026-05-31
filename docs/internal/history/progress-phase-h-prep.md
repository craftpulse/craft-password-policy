# Phase H prep — security audit polish + Phase 2 edition realignment (2026-05-14 → 2026-05-15)

Two arcs of work between Phase G close (2026-05-14, commit `be33546`) and the start of the Phase H QA pass:

1. **Security audit polish** — 17 commits across 2026-05-14 → 2026-05-15. Two named bundles (P2, P3) plus a series of single-issue fixes. Surfaced by a security review across the full 5.2.0 surface.
2. **Phase 2 edition realignment** — 4 commits on 2026-05-15. Password history, compliance presets, and expiry-reminder emails all moved from Pro to **every edition**. Comprehensive `docs/user/` rewrite to match.

Plus a comprehensive `docs/user/` rewrite for 5.2.0 ship state (separate commit chain) and a 5.3-candidate-bundle capture in `ideas.md` covering MFA / passkey / SSO audit coverage.

Pest suite went 786 → 802 passing / 0 skipped (1875 → 1924 assertions). ECS + PHPStan clean throughout. Schema unchanged at 2.11.0 — no new migrations.

## Arc 1: Security audit polish

Security review surfaced findings across the CP UI, controllers, audit-log surface, and HIBP listener. The remediation chain landed in three bundles (no formal "P1" — likely highest-severity findings were addressed inline as single-issue commits before the bundles).

### Single-issue fixes (2026-05-14 → 2026-05-15)

| Commit | Title | Surface |
|---|---|---|
| `71d8beb` | `fix(controllers): allowAdminChanges guards + exception leaks on notification-template surfaces` | Controllers |
| `47c1b46` | `fix(cp,a11y): edition gating + radiogroup keyboard + translator XSS + readOnly on CP UI` | CP a11y + XSS |
| `6bef758` | `refactor(users): move force-reset action from RetentionController to UserSecurityController` | User-edit surface |
| `baaf5c3` | `feat(notifications,siem,webhooks): native Cp::statusLabelHtml status pills` | Status UI |
| `20013a6` | `fix(notifications,permissions): sendNewDeviceAlert Pro guard + activity breadcrumbs + log-view permission` | Permissions |
| `6125dc4` | `fix(cp): polish — spacing utilities, button styling, divergent indicator, async→.then style` | CP polish |
| `ebae56e` | `docs(audit-logging): name Splunk HEC + Datadog explicitly as supported SIEM destinations` | Docs |
| `9285f37` | `fix(password-history): route password compare through Craft Security service` | Security primitive |
| `99f395e` | `fix(webhooks): don't leak exception message from actionRotateSecret` | Information disclosure |
| `6703c88` | `fix(hibp): drop sha1Prefix from login dedup cache key` | Cache-key privacy |
| `2c7c91d` | `fix(audit-export): bind download token to requesting admin` | Authorization scope |
| `8cad6ad` | `chore(events,audit-export,cp-nav): preventative polish from the security audit` | Cross-cutting polish |
| `61f47d1` | `fix(presets): NIST preset enables checkCommonPasswords for §3.1.1.2 conformance` | Preset correctness |
| `924f5e7` | `fix(audit): resolve user via UserEvent::$user on lock/unlock listeners` | Audit attribution |
| `e45b9aa` | `fix(webhooks): strip plaintext HMAC secrets from asModelSuccess JSON` | Secret exposure |

### P2 bundle (`e41878e`, 2026-05-15)

`fix(audit,webhooks): P2 bundle — canonicalisation, uninstall cleanup, confirm UX`. Three surfaces:

- **Audit canonicalisation hygiene.** Tighter `canonicalize()` rules — explicit handling of nested arrays + null values to ensure bit-identical bytes across PHP versions.
- **Uninstall cleanup.** `Install::safeDown()` extended to drop the new G7/G8/G9 tables + element-ified table data + their FK rows in `craft_elements`.
- **Confirm UX on destructive webhook actions** — `_webhooks/_edit.twig` gained confirm prompts on rotate-secret + delete.

### P3 bundle (`00e6c33`, 2026-05-15)

`fix(webhooks,siem,cp): P3 polish bundle — exception strings, button class, hidden attr`. Three smaller items:

- **Webhook + SIEM exception strings** generalised so no internal detail leaks to CP admin.
- **Button class normalised** on webhook edit form (was using inconsistent `btn submit` mix).
- **`hidden` attribute** preferred over `display: none` on edition-gated form sections — better a11y, screen readers skip cleanly.

## Arc 2: Phase 2 edition realignment (2026-05-15)

Material product positioning change. Three features moved from Pro-only to **every edition**, plus a major preset enhancement:

### `3fdeee5` — Password history moves to all editions

- `PasswordHistoryValidator` runs on every edition when `passwordHistoryCount > 0`.
- `SettingsController::actionSave` strip block no longer includes `passwordHistoryCount` / `passwordHistoryExpiryDays` — these are now universal settings.
- CP settings UI: history fields move out of the Pro-gated section into the always-visible block.
- Per-group history overrides (different counts per named policy) remain Pro — the Pro lever is **per-group granularity**, not history itself.

### `c2ae7b6` — CIS Controls v8 + global preset apply on every edition

- New `PolicyPreset::CIS_CONTROLS_V8` case in the enum. Safeguard 5.2 IG1/IG2/IG3 alignment: 14-char minimum, no complexity requirement (per CIS guidance), 365-day rotation (diverging from NIST's no-rotation stance — CIS explicitly recommends rotation alongside breach-driven changes).
- Five presets total: NIST 800-63B Rev 4, OWASP ASVS L1, PCI-DSS v4.0, CIS Controls v8, Strict Enterprise.
- **First four presets applicable as global defaults on every edition** via new "Apply Preset" settings surface (`SettingsController::actionApplyPreset`). Strict Enterprise remains Pro-only because it relies on Pro validators (sequential / repeated / contextual).
- Per-group named-policy CRUD (the CP page with editor) remains Pro-only.

### `ac04e01` — Expiry-reminder emails universal across editions

- Pro guards removed from `NotificationService::sendPasswordExpiryReminder` and `SendPasswordExpiryRemindersJob::execute()`.
- Lite installs use the **stock seeded template** from `EmailDefaults::all()`. No editor UI on Lite (that's the Pro lever).
- Pro adds the editor + activity log + resend + sender-overrides + token picker.
- Enterprise inherits all Pro features + the custom-template-path override.

### `d8f49fe` — Comprehensive user-doc rewrite

`docs/user/editions.md` feature matrix rewritten. `features/password-history.md`, `features/notifications.md`, `features/per-group-policies.md` updated to reflect the realignment. "Enterprise is not yet built" framing dropped throughout (Phase G shipped earlier this cycle). NIST 800-63B Rev 4 alignment section rewritten — `NIST_800_63B` preset is Lite-applicable globally. New "CIS Controls v8 alignment" section.

### Why the realignment

The realignment reflects a maturity assessment of the Lite tier: a free password-policy plugin that doesn't enforce reuse-prevention, doesn't ship presets for compliance buyers, and doesn't notify on expiry is *too* skeletal for the security category. Pulling these in widens the wedge against single-feature Lite competitors (Pwny, Enforce password) without cannibalising the Pro/Enterprise leverage. The Pro tier's per-group lever + advanced validators + front-end Twig surface + notification editor remains its differentiator.

Memory rule `project_audit_capture_principle.md` (codified in F2) is the architectural anchor: capture on every edition; gate exposure not capture. The realignment extends this from audit capture to feature enforcement — Lite users now get the security-critical mechanisms, Pro users get the admin-grade controls on top.

## Arc 3: Comprehensive user-doc rewrite

Separate from the edition realignment doc rewrite (`d8f49fe`), a broader sweep of `docs/user/` landed earlier on 2026-05-15:

| Commit | Coverage |
|---|---|
| `584d9c0` | `docs(readme,index): refresh entry-point docs for 5.2.0 ship state` |
| `61c4017` | `docs(features): rewrite audit-logging, force-reset, notifications for 5.2.0 ship state` |
| `52ac336` | `docs(features): rewrite per-group-policies, password-history, validators + polish user-index` |
| `d2966d3` | `docs(features): add Phase G feature docs — verifier, dashboard, blocklist, SIEM, webhooks, export, cooldowns` |
| `c7cdf7d` | `docs(operations): add upgrade-from-5.1, cron-setup, compliance-frameworks + refresh gc-and-retention` |
| `c6be81c` | `docs(reference): add SiemForwardAttemptEvent + rewrite database-schema + refresh ajax-validate` |
| `1ca4433` | `docs(editions): add NIST Rev 4 alignment + compliance phrasing discipline` |
| `60a3090` | `docs(compliance): correct framework clause citations across audit-logging doc` |
| `149400b` | `docs(changelog): comprehensive 5.2.0 rewrite + bring forward 5.1.2 entry` |
| `732974a` | `docs(ideas): record 5.3 candidate bundle — MFA / passkey / SSO audit coverage` |

User-facing docs are current as of 2026-05-15. Sample-check confirms accuracy. **Note:** `features/notifications.md` was rewritten before the Phase 2 edition realignment, then re-touched in `d8f49fe`. `features/audit-logging.md` and the Phase G feature docs were authored against the post-Phase-G shipping surface.

## Cumulative metrics at Phase H prep close

- **Suite:** 802 passing / 0 skipped / 1924 assertions (+16 / +49 over Phase G close).
- **Schema:** unchanged at 2.11.0.
- **ECS + PHPStan:** clean, baseline unchanged.
- **Commits:** ~35 since Phase G close (`5c2e954` → `d8f49fe`).
- **Branch:** `5.x` fully synced to `origin/5.x`. Working tree clean.

## What's next: Phase H QA pass

Manual test register currently 78/79 PASS against the pre-Phase-G surface. Needs T-rows for:

- **T14.x – T22.x** — Phase G surfaces (hash chain, verifier CLI, compliance dashboard, SIEM, webhooks, audit export, alert cooldowns, per-policy blocklist, custom template paths, Enterprise notification keys).
- **T24.x** — Phase 2 edition realignment (history universal, preset apply universal, expiry email universal, Strict Enterprise still Pro-gated).
- **T25.x** — Security audit polish verifications (authorization scopes, info disclosure, secret stripping, cache-key privacy).

Authored 2026-05-18 alongside this log. See `manual-tests.md`.

Once the QA pass runs end-to-end (multi-hour focused user session), the next gates are:

1. Tag 5.2.0 — `composer.json` stays at `5.2.0-alpha.1` per user direction. Tag will be applied separately.
2. Plugin Store listing rewrite.
3. Marketing copy.

5.3 work seeded in `ideas.md` (lead feature: auth-event audit for MFA / passkey / SSO lifecycle).
