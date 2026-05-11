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
