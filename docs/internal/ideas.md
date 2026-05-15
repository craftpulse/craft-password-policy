# Ideas & Future Concepts

Brainstorming notes from the v5.2.0 build sessions. Not committed to any of these — they need further research, design, and prioritization before becoming plan items.

---

## Policy Transition Grace Periods

**Date:** 2026-04-26
**Context:** When a group moves from Policy X to Policy Y (e.g., NIST → PCI-DSS), every user in that group is suddenly under a stricter regime. Their existing passwords may not comply.

**The idea:** An explicit admin-initiated "policy transition" with a deadline and escalating enforcement. Not automatic on every policy tweak — only when a group's policy assignment changes entirely.

**How it would work:**
1. Admin reassigns Group A from Policy X to Policy Y
2. System detects this is a policy change (not a new assignment)
3. Admin sets a grace period (e.g., 30 days) and consequence (notify only / force reset / soft-lock)
4. Affected users are notified (email, CP banner, front-end Twig variable)
5. Escalation during grace period (reminders at intervals)
6. After deadline, enforcement kicks in (force password reset or redirect to change password on every login)

**What makes it interesting:**
- Nobody does this well. Entra, Okta, 1Password — all require manual admin intervention for policy transitions.
- It's auditable: "Policy changed on date X, grace period 30 days, user Y notified 3 times, forced reset on date Z." Compliance gold.
- Builds on existing infrastructure: NotificationService, `passwordResetRequired` flag, condition rules, PolicyResolverService.

**Key design question:** The grace period lives on the **assignment event** (junction table `dateCreated`), not on the policy itself. Tweaking a policy's minLength from 12 to 14 shouldn't restart the clock for everyone.

**Technical challenge:** We can't check if an existing password meets a new policy without the plaintext. We don't know if a password is "too short" after it's hashed. So "non-compliant" really means "hasn't changed password since the policy changed." That's actually fine — it's what every other system does. Assume non-compliance, require a fresh password under the new rules.

**Edition:** Likely Enterprise. Pro gets named policies and merge logic. Enterprise gets the compliance workflow.

**Research done:** Checked Microsoft Entra ID, Okta, 1Password Business, NIST 800-63B, PCI-DSS v4.0. None address policy transition grace periods directly. Entra's closest concept is Conditional Access "report-only" mode (deploy, monitor, then enforce). NIST explicitly doesn't address policy transitions.

---

## Background Breach Monitoring (HIBP Watchtower)

**Date:** 2026-04-26
**Context:** Currently HIBP checks happen at password change time. But breaches happen continuously — a password that was clean yesterday might appear in a new breach dump tomorrow.

**The idea:** Periodically re-check passwords against HIBP without needing the plaintext. Inspired by 1Password Watchtower.

**The k-anonymity prefix approach:**
- At password creation/change, store the first 5 chars of `SHA1(plaintext)` — the k-anonymity prefix
- This is safe to store: maps to ~500-800 possible passwords per bucket, tells an attacker nothing useful
- Background cron job: for each stored prefix, call HIBP API, check if the bucket has grown
- If significant growth in a user's bucket → flag for proactive password change
- Probabilistic only — can't confirm exact match without the full SHA-1 suffix

**Why not store the full SHA-1?**
- HIBP uses unsalted `SHA1(plaintext)` — rainbow tables exist, GPU cracking is billions/sec
- Storing full SHA-1 alongside bcrypt effectively downgrades security from bcrypt to SHA-1
- 1Password Watchtower avoids this because it's client-side (has the plaintext in the vault)
- We're server-side — different threat model

**Three options evaluated:**
- **Option A: Check at login only (no storage)** — current plan. Catches breaches when users log in. Dormant accounts stay unflagged. Simple, secure, no trade-offs.
- **Option B: Store 5-char prefix only** — safe. Enables probabilistic monitoring ("this bucket grew, you should change your password") and probabilistic duplicate detection (~1/500 false positive rate). Interesting for analytics: "estimated X% breach exposure." Not actionable per-user.
- **Option C: Store encrypted full SHA-1** — AES-256-GCM with server key from env var. Enables exact monitoring and exact duplicate detection. But if DB + key both compromised, all passwords are exposed via fast SHA-1 cracking. Defense-in-depth says no.

**Decision:** Option A for Pro (check at login). Option B worth exploring for Enterprise analytics dashboard — "estimated breach exposure" as a compliance metric without the security trade-off. Option C rejected.

**Duplicate detection angle:** With stored prefixes, you could estimate how many users share passwords (same prefix = ~1/500 chance of sharing). Useful for compliance dashboards ("X users may share passwords") but not for flagging individuals.

**Edition:** A = all editions (already planned). B = Enterprise only (analytics/compliance feature).

---

## Adversarial Test Suite — "the security plugin tests itself"

**Date:** 2026-04-30
**Context:** T7.3 (edition stripping verification) currently passes via code review only. The unconditional `unset()` blocks in `SettingsController::actionSave()` make the strip provably correct, but there's no automated positive test that an attacker-shaped POST actually gets stripped. Same gap applies to other security boundaries (CSRF on every endpoint, permission checks, rate-limit-style validators).

**The idea:** A dedicated "adversarial" test suite that pokes the plugin from the outside the way an attacker would, on the assumption that *the security plugin should be the most rigorously security-tested plugin in the codebase*. Meta-angle is the marketing value too — "we test our own security plugin against itself."

**Concrete tests to write (Pest, post-P2.5):**

- **Edition smuggling:** With plugin on Lite, POST a settings save with `passwordHistoryCount=99`, `enableAuditLog=1`, `siemEndpointUrl='https://attacker.com'`. Assert: project.yaml after save contains none of those keys.
- **CSRF stripping:** Submit any state-changing POST without a CSRF token. Assert: rejected before the action runs.
- **Permission smuggling:** As a non-admin user with no plugin permissions, POST every state-changing action. Assert: 403 on every one.
- **Mass-assignment via raw POST:** POST `settings[id]`, `settings[uid]`, `settings[__construct]` etc. to actionSave. Assert: ignored.
- **Validator bypass:** Submit passwords with embedded null bytes, unicode normalization tricks, RTL override chars. Assert: validators handle these correctly without throwing.
- **HIBP fail-closed timing:** Patch the HIBP client to return slowly vs immediately on failure. Assert: response time variance is below a threshold.
- **Migration rerun safety:** Apply our consolidated upgrade migration twice in a row. Assert: idempotency holds, no duplicate history rows, no project config corruption.

**Why interesting:** every other Craft plugin tests its happy paths. A security plugin should test its boundaries. The test suite itself becomes a marketing asset ("see how we red-team ourselves").

**Edition:** test infrastructure is cross-edition. Specific tests gate on edition-relevant features. Pairs with P2.5 (general test scaffold) — adversarial tests are an extension once Pest is wired up.

**Status:** parked. Add to roadmap once P2.5 lands.

---

## Audit log levels against security.md (5.2.x cleanup)

**Date:** 2026-05-02
**Context:** Phase E4's `GuzzleHibpClientTest` uncovered that `GuzzleHibpClient::query()` was logging non-2xx-non-429 errors at `Logger::LEVEL_ERROR`, contradicting `security.md` which prescribes `WARNING` for fail-open transient outages ("a single HIBP CDN burp shouldn't page someone"). Fixed inline as a one-off, but the root cause is broader: nobody has audited every `->log()` / `Craft::error()` / `Craft::warning()` call site in the plugin against security.md's level guidance.

**The audit:** grep every `LEVEL_ERROR`, `LEVEL_WARNING`, `Craft::error`, `Craft::warning`, `$plugin->log` in `src/`, cross-reference against `security.md`'s level prescriptions per surface (HIBP, blocklist, validators, controllers, jobs). Anywhere they diverge, decide: is the code wrong (downgrade/upgrade the log level) or is the doc wrong (update security.md)? Capture the decision in the same commit as the fix.

**What it'll likely surface:**
- More HIBP-side ERROR-vs-WARNING divergences (the cohort of `query()` errors was just one).
- Queue job failure logging — should batch failures be ERROR (each one) or WARNING (only when retry-budget exhausted)?
- ValidationController failures — currently logs at the framework default; security.md doesn't prescribe a level. Probably leave unprescribed but add a row to security.md confirming.
- Any "audit log" entries (Phase G) need their own level guidance — those are different from operational logs.

**Why 5.2.x and not 5.3:** log-level adjustments are observability fixes, not features. Operators relying on alert thresholds tied to ERROR-level entries will see noise drop after the fix; not breaking, but worth landing as soon as there's a polish window.

**Test impact:** any existing test that asserts on log level (currently just `GuzzleHibpClientTest::it_returns_null_on_a_500_server_error_and_logs_at_warning`) gets flipped if the corresponding fix changes the level. Tests that don't assert on level are unaffected. Add level assertions where they'd guard against silent regressions in the audited surfaces.

**Status:** parked as 5.2.x candidate.

---

## Phase D leftovers — quality polish

**Date:** 2026-05-03
**Context:** Two small surfaces noted during the Phase D build that deliberately weren't fixed inline because each one is either out-of-scope, low-impact, or needs customer signal before acting.

### `BREACHED_RECENT_DAYS = 90` and `EXPIRING_SOON_DAYS = 7` are hardcoded

`UserIndexService` ships these as class constants. The composite-status priority lookup uses them to decide "should this user show as breached?" / "expiring soon?". They're reasonable defaults — 90 days matches HIBP's typical breach disclosure latency, 7 days matches the existing `expiryReminderDays` cadence — but customer input from compliance-buyer accounts may want either as a CP setting.

**Why not fix now:** no customer has asked. Promoting to settings before the demand exists is YAGNI. The constants are documented in `UserIndexService` so a future Phase G "compliance dashboard customisation" feature has a known seam.

**Edition / scope:** Pro-tier setting (Lite installs already see the columns; the threshold tuning is a Pro / Enterprise compliance affordance). Add to `SettingsModel` + the retention/breach-detection settings page when demand surfaces.

### Per-user policy resolver iteration in the Pro+Team+ preload

`UserIndexService::_preloadResolvedPolicies()` iterates each user one at a time and calls `PolicyResolverService::resolveForUser($user)` per user. The resolver's own caching helps within a single render (same user resolved twice → second call hits cache). But across a 50-user user-index page on Pro+Team+, that's 50 distinct resolver calls — each one walks the user's groups + queries policy junction rows + merges.

**Why not fix now:** the user index page is paginated, `pp:change-user-passwords`-restricted, and rendered infrequently. Per-resolve cost is in the milliseconds. At current customer scale (Pro tier targets at < 10k users typically), it's not load-bearing. If a customer reports user-index slowness post-launch, batch-resolve becomes a worthwhile refactor: `resolveForUsers(array $users): array<int, SettingsModel>` walking the policy junction once for the whole batch and merging in-memory.

**Edition / scope:** internal optimisation. Land if profiling shows it's a bottleneck — otherwise YAGNI. The `PreloadBatchingTest` query-count contract holds the line at "preload runs at most N+M queries"; a future `resolveForUsers` swap would add only one additional query class without changing the contract shape.

**Status:** both parked, captured here so the next session knows the surface is intentional, not overlooked. Combine into a single 5.2.x polish commit if either ships — they're both small, both in `UserIndexService`, and share the "we noticed but didn't act" framing.

---

## SIEM forwarder — RFC 6587 octet-count framing as opt-in

**Date:** 2026-05-07
**Context:** G8 (commit `160808a`) ships syslog-over-TLS with non-transparent newline framing (`$frame . "\n"`). This works against every major SIEM receiver (Splunk, Elastic, Datadog, Logstash, rsyslog) tested during build, but RFC 6587 §3.4.2 explicitly notes non-transparent framing is "unreliable" for messages with embedded LFs. Plugin-emitted RFC 5424 frames don't contain embedded LFs today, so there's no current-correctness issue — this is interop hygiene only.

**Proposal:** Add a `framingMode` enum field to `SiemForwarderModel` with values `non-transparent` (default) + `octet-count`. CP edit screen exposes the choice with help text linking to RFC 6587. `SiemService::_writeToSocket()` switches on the mode: octet-count produces `strlen($frame) . ' ' . $frame` instead of `$frame . "\n"`. Schema migration adds a column.

**Why deferred:** non-blocker for 5.2.0; no current-correctness issue; better to ship after a Phase 12 REST surface lands and operators have real production traffic to inform the default choice.

**Estimated effort:** Half-day. One column, one enum, one branch in `_writeToSocket`, one CP form field.

---

## 5.3 candidate bundle — auth-event coverage (MFA / passkey / SSO)

**Date:** 2026-05-15

**Context:** The plugin's 5.2.0 audit log captures password change, blocklist hit, HIBP match, settings save, retention purge, policy change, alert cooldown fire, SIEM forward attempt, webhook delivery, audit export. **Auth-method lifecycle is a complete blind spot** — TOTP setup/removal, passkey registration/use/deletion, recovery-code generation/download, elevated-session events. The user flagged this gap explicitly: "we barely touch grounds on MFA/Passkey generation. Or SSO there are SSO traces in core and I know P&T only sets it up under enterprise accounts."

**The headline finding from May 2026 research:** Craft 5 fires **no events** on the auth-method lifecycle. The entire auth surface ships exactly one event, `User::EVENT_BEFORE_AUTHENTICATE` (password attempts only — `$password === null` for the passkey flow). `craft\controllers\AuthController` actions (`actionVerifyTotp`, `actionVerifyPasskey`, `actionDeletePasskey`, `actionRemoveMethod`, `actionGenerateRecoveryCodes`, `actionDownloadRecoveryCodes`) are silent. `craft\services\Auth` exposes only `EVENT_REGISTER_METHODS` (extension hook, not audit signal).

This is verified against the live `craftcms/cms` 5.x source (May 2026). Trails — our nearest competitor on the audit-log surface — has the same ceiling. WordPress's parallel audit-log plugins capture passkey/TOTP events because WordPress fires explicit events; Craft is the gap.

**Compliance framework anchor:** NIST 800-63B Rev 4 (finalised 31 July 2025) requires phishing-resistant MFA at AAL2 (offer) and AAL3 (require). NIS2 ENISA Q1 2026 guidance reads Article 21(2)(j) as "MFA where appropriate" — and clarifies that "appropriate" means a documented risk assessment, not optional. BSI January 2026 implementation guide names FIDO2 / WebAuthn passkeys / smartcards as acceptable; SMS-OTP excluded post-January 2026. **12-month forensic auth trail retention** is a published bar. PCI DSS v4.0.1 §8.4 requires logging of MFA admin access.

So: there's a verified gap in Craft core, a verified gap in the closest competitor, a verified compliance framework anchor, and our shipping `AuditLogElement` + retention infrastructure to slot the captures into. This is the strongest 5.3 wedge.

---

### Auth-event audit: MFA + passkey + recovery-code lifecycle capture (5.3 lead feature)

**The idea:** Capture every auth-method lifecycle action as an `AuditLogElement` row. Twelve new event types covering TOTP setup completed / removed, passkey registered / used / deleted, recovery codes generated / downloaded, auth method added / removed, elevated session started / failed / extended.

**How it would work:**
1. Listener on `yii\base\Controller::EVENT_AFTER_ACTION` filtered to `auth/*` action segments (`Craft::$app->getRequest()->getActionSegments()`).
2. Inspect `Craft::$app->getResponse()->statusCode` + the resolved action name to classify the outcome — 200 + `verify-passkey-creation` → passkey registered; 200 + `delete-passkey` → passkey deleted; 200 + `remove-method` → TOTP/recovery removed; 400/429 → failed attempt.
3. New `AuditEvent::AUTH_METHOD_*` constant family with twelve members.
4. Map captured events into the existing `ALLOWED_DETAILS_BY_EVENT` allowlist (fail-closed per the G5 invariant).
5. Document the controller-action → audit-event mapping in `docs/user/reference/audit-events.md`. This is the brittle seam — controller action names are documented but not contract-guaranteed across Craft minor releases.
6. **Open an upstream PR** proposing `Auth::EVENT_AFTER_METHOD_SETUP` / `EVENT_AFTER_METHOD_REMOVED` / `EVENT_AFTER_PASSKEY_CREATED` / `EVENT_AFTER_PASSKEY_DELETED` + `AuthController::EVENT_AFTER_VERIFY_TOTP` / `EVENT_AFTER_VERIFY_PASSKEY` to Craft core. Capture the PR URL in our docs so we can swap from the action-segment seam to first-party events once they merge (likely Craft 5.7 or 6.0). Until then, we run the seam — Craft has been responsive to ecosystem audit-log requests historically (`UserGroups::EVENT_BEFORE_APPLY_GROUP_DELETE` landed in 4.x specifically for our case).

**What makes it interesting:** Nobody in the Craft ecosystem captures this. Trails doesn't. The 12-month forensic-trail bar (NIS2 + ENISA) is published, not speculative. Pure additive — no schema changes (uses the existing `AuditLogElement`). Builds entirely on shipped 5.2.0 surfaces (`AuditLogElement`, `AuditLogService`, retention GC, `ALLOWED_DETAILS_BY_EVENT` allowlist).

**Edition:** Enterprise (audit log is Enterprise; this extends the same table). Capture remains universal per `project_audit_capture_principle.md` — the listener fires on every edition; the exposure (CP audit-log index + reports) is Enterprise-only.

**Risk:** Controller-action-name coupling. Craft renames an action → we drop a capture silently. Mitigate by pinning the Craft version range we've tested against in the plugin's `composer.json` and running an integration test that asserts the action segments still resolve. Document the mapping prominently.

**Estimated effort:** 3–5 days. Listener wiring + twelve event constants + the docblock+test for each mapping + the upstream PR.

**Status:** Strongest single 5.3 candidate. Recommended as the 5.3.0 lead feature.

---

### Phishing-resistance posture report

**The idea:** Compliance dashboard widget + console command that classifies each user's strongest active auth method into NIST AAL tiers and surfaces the population posture. "X% AAL1, Y% AAL2, Z% passkey-AAL2+."

**How it would work:**
1. New `AuthPostureService::classifyUser(User $u): AuthAssuranceLevel` enum mapping.
2. Reads `Craft::$app->getAuth()->getActiveMethods($u)` + `hasPasskeys($u)` — both are cheap cached lookups in Craft core.
3. AAL mapping: password-only → AAL1; password + TOTP → AAL2; passkey → AAL2+ (we can't distinguish synced vs device-bound from server-side per the WebAuthn spec — report as "passkey AAL2+").
4. Compliance dashboard widget (G3 — already shipped): stacked-bar widget, drill-through to user-index filtered view.
5. `password-policy/auth-posture/report --json` console command for CI / compliance pipelines.

**What makes it interesting:** Compliance-buyer GTM — NIS2 + NIST AAL framing maps directly to a population posture metric the buyer can hand to an auditor.

**Caveats:** Document the synced-vs-device-bound passkey distinction prominently. Server-side passkey verification can't tell which kind it's verifying.

**Edition:** Enterprise.

**Estimated effort:** 1-2 days. Read-only on Craft's auth state; no new tables. Pairs naturally with the auth-event audit candidate above.

**Status:** Quick win. Ships 5.3.

---

### Per-policy MFA requirement (`requireMfa` on PolicyElement)

**The idea:** Add `requireMfa` (bool) and `requireMfaMethodTypes` (JSON enum list, e.g. `['passkey']` or `['passkey', 'totp']`) to `PolicyElement`. Pro-tier policies can mandate MFA for their assigned groups; the resolver merges these like every other field.

**How it would work:**
1. New nullable columns on the `passwordpolicy_policies` table (`requireMfa TINYINT(1)`, `requireMfaMethodsJson JSON`).
2. `PolicyResolverService::resolveForUser()` merges these — most-restrictive-wins like the rest of the model.
3. Reuse the HIBP-on-login listener wiring (`User::EVENT_BEFORE_AUTHENTICATE`): when the resolved policy requires MFA *and* the user has no active method, write an audit event (`MFA_REQUIRED_BUT_MISSING`) and optionally redirect to setup. **Don't block the login** — Craft core's system-level `requireTwoStepVerification = 'admins' | groups` already handles enforcement when toggled. Our value-add is the per-policy granularity + the audit trail.
4. CP edit-policy screen: new "MFA" tab with the lightswitch + method-type multi-select.
5. Compliance dashboard surfaces non-compliant-user counts per policy.

**What makes it interesting:** Layers per-policy MFA on Craft's system-level enforcement — finer grain than core offers. The audit-trail-for-non-compliance pattern is the differentiator vs the binary core toggle.

**Foundation-first check:** `PolicyElement` ships in 5.2.0 (commit `2809614`). Adding nullable columns in 5.3 is additive (no rename, no restructuring). Safe per `feedback_foundation_first_no_refactor_deferrals.md`.

**Edition:** Pro for per-policy `requireMfa`; Enterprise for the audit-event side.

**Estimated effort:** 3–5 days. Schema + resolver merge + CP UI + audit-event integration + tests.

**Status:** Ships 5.3.

---

### Recovery-code re-issue audit + throttle

**The idea:** Audit recovery-code generation and download events; add an optional throttle on re-issue per N hours per user; send a tamper-evident notification to the user when their recovery codes are re-generated (independent of who triggered it).

**Why this matters:** Recovery-code re-issue is one of the highest-signal indicators of account compromise on a 2FA-protected account. A compromised admin session can re-generate codes (invalidating existing ones) and download them with zero audit signal today.

**How it would work:**
- Folds into the auth-event audit listener above — `RECOVERY_CODES_GENERATED`, `RECOVERY_CODES_DOWNLOADED` are two of the twelve event types covered.
- Add `recoveryCodeReissueRateLimit` setting (default off; configurable max generations per N hours). Soft-block via 429 + `RECOVERY_CODES_RATE_LIMITED` audit event when hit.
- Reuse `NotificationLogElement` + the existing `_dispatch()` path for the user-notification side. New template key `recovery-codes-reissued` seeded via `EmailDefaults::all()`.

**Edition:** Audit + throttle = Enterprise. User notification = Pro (security-hygiene affordance).

**Estimated effort:** Half-day on top of the auth-event audit work. Folds in.

**Status:** Sub-feature of the auth-event audit candidate. Ships 5.3.

---

### Auth-attempt anomaly detection: new-country / new-device flags

**The idea:** Geo-IP enrich auth events (post-5.2.0 `AuditLogElement` row), flag "first auth from this country" / "first auth from this device fingerprint." Pure observation — no blocking, no adaptive MFA (that's IdP territory).

**How it would work:**
1. New optional column on `AuditLogElement` for `geoCountry` / `geoCity`. Lazy enrichment from a configurable provider — default to MaxMind GeoLite2 self-hosted file (FOSS data file; license permits self-hosted lookup).
2. `AuthAnomalyService::isFirstAuthFromCountry($user, $country): bool` queries the audit log history.
3. If anomalous, emit `AUTH_NEW_GEO` event + optional email-to-user notification.
4. Device fingerprint angle: hash of `(User-Agent + Accept-Language + IPs /24 network)` — same kind of indicator the existing new-device-alert path uses.

**Foundation-first check:** Adding nullable columns to `AuditLogElement` (shipped in 5.2.0) is additive. Safe.

**Edition:** Enterprise.

**Estimated effort:** Multi-day (3-5). Provider abstraction + lazy enrichment + new column + tests.

**Status:** Defer-or-ship depending on 5.3 capacity. Ships when it ships.

---

### SSO event-bridge: surface Flipbox SAML / miniOrange auth attempts in our audit log

**The idea:** Self-hosted Craft 5 SSO is fragmented — Flipbox saml-sp ($69/yr, current 5.1.3 on 2025-01-29) and miniOrange single-sign-on ($paid, multi-protocol) are the dominant pair, neither a FOSS leader. Both ultimately call `Craft::$app->getUser()->login($user)` after SAML assertion validation — that path does NOT trigger `User::EVENT_BEFORE_AUTHENTICATE` because the password path isn't taken. So SSO logins are invisible to our existing auth-event listeners.

**How it would work:**
1. New optional `SsoBridgeService`. At plugin init, check `Craft::$app->getPlugins()->isPluginEnabled('saml-sp')` and `'craft-single-sign-on'`.
2. If enabled, attach listeners on those plugins' own events (e.g. Flipbox's `flipbox\saml\sp\events\AuthEvent`). We'd document the supported event surface per plugin in our docs.
3. Map their assertions to our new `AuditEvent::AUTH_SSO_*` family: `SSO_AUTH_REQUESTED`, `SSO_USER_PROVISIONED`, `SSO_MAPPING_CHANGED`, `SSO_GROUP_RESOLVED`.
4. Pin the supported plugin version ranges in our docs; fall back to a request-log heuristic if the third-party events disappear.

**Why interesting:** The only way to unify "MFA + SSO + password" audit trails in one Enterprise compliance view on self-hosted Craft. Doesn't require P&T to build first-party SSO into core — we cover the existing ecosystem.

**Risk:** Coupling to third-party plugin event names. Mitigate via version pinning + integration tests + fallback heuristic.

**Status:** **Spike-then-decide.** Half-day spike to confirm event surfaces in Flipbox + miniOrange source. Multi-day implementation if viable. Surface the spike result before committing.

**Edition:** Enterprise.

---

### Auth posture Twig surface: `craft.passwordPolicy.posture(user)`

**The idea:** Site builders want to render a compliance banner on the front end ("Your account is missing MFA. Set it up here."). Today they'd write the logic by hand. Wrap it into a single answer.

**How it would work:**
- New `AuthPostureService` (also reusable by the dashboard widget above).
- `posture(currentUser)` returns a `PostureReport` value object: `hasPassword`, `hasMfa`, `mfaIsPhishingResistant`, `passwordIsExpired`, `passwordIsBreached`, `recommendedActions[]`.
- Variable method on `PasswordPolicyVariable` (both `craft.passwordpolicy` + `craft.passwordPolicy` handles).
- Optional Twig tag that renders a default no-framework HTML banner with edition-aware affordances.

**What makes it interesting:** Builds on the P1.12 front-end Twig surface we already ship. Lite gets read-only `hasMfa`; Pro/Enterprise get the rich phishing-resistance / expiry flags.

**Edition:** Lite (read-only flag) + Pro (rich report).

**Estimated effort:** 1-2 days. Pure additive.

**Status:** Quick win. Ships 5.3.

---

### Rejected: custom auth method shipping a "TOTP secret blocklist"

Surfaced and rejected during the May 2026 research. TOTP shared secrets are 80 bits from `random_bytes`, not user-chosen — a "blocklist for TOTP secrets" doesn't address a real threat. This is the kind of "reinvent MFA inside our plugin" the constraints flag against. Captured here so it's not re-proposed.

---

## 5.3.0 scope recommendation

**Lead feature:** Auth-event audit (MFA + passkey + recovery code lifecycle capture). Biggest competitive wedge; addresses verified gaps in both Craft core and Trails; lines up with NIS2 ENISA Q1 2026 guidance; additive only; seeds three follow-on features.

**Pair with:**
- Phishing-resistance posture report (1-2 days; reuses Auth service reads)
- Recovery-code re-issue audit + throttle (folds into auth-event audit; half-day)
- Auth posture Twig surface (1-2 days; front-end-side reuse of AuthPostureService)

**Stretch:**
- Per-policy `requireMfa` on `PolicyElement` (3-5 days; schema add + CP UI + resolver merge)
- Geo-IP anomaly enrichment (3-5 days; new column + provider abstraction)
- SSO event-bridge (spike first; multi-day if viable)

**Out of scope:**
- First-party SSO implementation. We're a password-policy plugin, not an IdP. Stay in observation lane.
- Replacing Craft core's TOTP / WebAuthn implementations. Augment, don't replace.

**Upstream PR:** Open one against `craftcms/cms` proposing `Auth::EVENT_AFTER_METHOD_SETUP` + friends. Capture the PR URL in our docs. If it merges, we graduate off the controller-action-segment seam in 5.4 or 6.0.

**Foundation-first verdict:** All recommended candidates are additive — new audit events into a shipped table, new columns onto shipped elements, new service methods, new Twig surface. Zero schema renames, zero controller path changes, zero permission renames. Per `feedback_foundation_first_no_refactor_deferrals.md` these defer cleanly.

