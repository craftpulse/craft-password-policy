# Compliance Frameworks

This page maps every Pro and Enterprise feature in the plugin to specific clauses across seven compliance frameworks. The citations are anchors for an operator's evidence package, they're not certifications. The plugin provides specific technical measures that controllers can rely on as part of their framework obligations.

> [!WARNING]
> **No plugin can make you compliant**
>
> Certification requires an auditor. What you get here is a set of technical measures you can point at, mapped to the clause that asks for them. When you write your own evidence package, cite the clause number rather than the framework name: an auditor reads the clause text.

The seven frameworks covered:

- [NIS2 Directive (EU 2022/2555)](#nis2)
- [NIST SP 800-63B Rev. 4](#nist-800-63b-rev-4)
- [PCI DSS v4.0.1](#pci-dss-v401)
- [CIS Controls v8](#cis-controls-v8)
- [ISO/IEC 27001:2022 + 27002:2022](#isoiec-270012022)
- [SOC 2 (AICPA TSC 2017 + 2022 Revised Points of Focus)](#soc-2)
- [GDPR (Regulation EU 2016/679)](#gdpr)

## Quick reference matrix

| Feature | NIS2 | NIST | PCI | CIS v8 | ISO | SOC 2 | GDPR |
|---|---|---|---|---|---|---|---|
| Per-group named policies | Art. 21(2)(g), (i) | §3.1.1.2 | §8.3.6 | 5.2 (per-account) | A.5.15, A.5.17 | CC6.1 | Art. 25 |
| Password history | Art. 21(2)(g) | §3.1.1.2 (re: reuse) | §8.3.7 | PPG (last 5) | A.5.17 | CC6.1 | - |
| HIBP at change time | Art. 21(2)(g) | §3.1.1.2 SHALL | §8.3.5 | PPG (breach check) | A.5.17 | CC6.1 | - |
| HIBP-on-login (Pro) | Art. 21(2)(g) | §3.1.1.2 SHALL | §8.3.5 | PPG (continuous) | A.5.17, A.8.15 | CC6.1, CC7.2 | - |
| Custom blocklist | Art. 21(2)(g) | §3.1.1.2 SHALL | §8.3.5 | PPG (deny list) | A.5.17 | CC6.1 | - |
| Lockout (Craft core) | Art. 21(2)(g) | §3.2.2 | §8.3.4 | 6.x | A.5.15 | CC6.1 | Art. 32(1)(b) |
| Force-reset actions | Art. 21(2)(g), (i) | §3.1.1.2 | §8.3.5 | PPG (rotation on compromise) | A.5.15 | CC6.3 | Art. 32(1)(b) |
| Audit log (Enterprise) | Art. 21(2)(g), (i) | - | §10.2, §10.3 | 8.x | A.8.15, A.5.33 | CC7.2, CC8.1 | Art. 5(1)(f), 32(1)(d) |
| Hash-chained rows | Art. 21(2)(g) | - | §10.3 | 8.x | A.5.33 | CC7.2 | Art. 32(1)(b)(d) |
| Verifier CLI | - | - | §10.3 | 8.x | A.5.33 | CC7.2 | Art. 32(1)(d) |
| Policy change diffs | Art. 21(2)(g) | - | §10.2 | 8.x | A.5.37, A.8.15 | CC8.1 | Art. 25 |
| Per-event PII allowlist | Art. 21(2)(g) | - | §10.2 | - | A.8.15 | CC6.1 | Art. 5(1)(f), 25 |
| `CRAFT_AUDIT_PII_KEY` rotation | - | - | - | - | A.5.17 | CC6.3 | Art. 17, 25, 32(1)(b) |
| SIEM forwarders | Art. 21(2)(g) | - | §10.2 | 8.x | A.8.16 | CC7.2 | - |
| Webhooks | Art. 21(2)(g) | - | §10.2 | 8.x | A.8.16 | CC7.2 | - |
| Retention purge (≥365 days) | Art. 21(2)(g) | - | §10.5.1 | 8.x | A.5.33 | CC7.2 | Art. 5(1)(e), 17 |

The rest of this page is the per-framework drilldown.

## NIS2

**Directive (EU) 2022/2555, Cybersecurity Risk Management Measures**

Transposition status as of May 2026: 21/27 EU Member States transposed. **Hungary's first mandatory audit deadline is 30 June 2026**: the sharpest single-jurisdiction enforcement hook in the EU. Other Member State deadlines vary; consult ENISA's NIS2 transposition tracker for current status.

Article 21 is the relevant article for password-policy + audit measures.

### Article 21(2)(g) basic cyber hygiene practices

The plugin's HIBP-on-login + audit log + password policy + blocklist enforcement together constitute "basic cyber hygiene practices and cybersecurity training" controls per Article 21(2)(g).

- **HIBP-on-login** continuously screens user credentials against the global breach corpus. Per ENISA's Q1 2026 implementation guidance, "continuous credential monitoring" is a basic cyber hygiene control under (g).
- **Audit log** records who changed what password, when, with what outcome: the evidence trail that controllers need to demonstrate (g) is operationally enforced.
- **Per-group named policies + presets** make the framework-specific configuration auditable as project config (versioned, reviewable).
- **Blocklist** rejects credentials known to be common or breached: the control that translates (g) into a specific enforcement.

### Article 21(2)(i) human resources security, access control, asset management

Per-group named policies are the literal implementation of an access control policy that varies by user role. Plus:

- **Per-group policy assignment** maps Craft user groups (admins, editors, customers, vendors) to differentiated password rules: the textbook (i) control.
- **Force-reset actions + audit propagation** provide the change-management evidence (i) expects.

### Article 21(2)(j) MFA: explicitly NOT us

Article 21(2)(j) requires MFA "where appropriate." **MFA is Craft core's territory, not this plugin's.** The plugin's password policy is *complementary* to your MFA strategy under (j); don't cite (j) as a primary mapping for password policy alone.

If you're configuring Craft's native TOTP / passkey support to satisfy (j), the plugin's audit log captures the password-related events that complement the MFA-related events Craft fires.

### Fines

Essential entities up to €10M or 2% of global revenue; Important entities up to €7M or 1.4%. The audit log + evidence-package workflow is the operator-facing surface that demonstrates "appropriate technical measures" if a competent authority demands evidence.

## NIST 800-63B Rev. 4

**SP 800-63B Revision 4, Authentication and Authenticator Management**

Finalised 31 July 2025. Verified against `nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf`.

The plugin's `NIST_800_63B` preset is built to satisfy the relevant SHALL requirements from Rev. 4 §3.1.1.2 + §3.2.2.

### §3.1.1.2: Memorized secret verifiers

Quoting the spec:

> *"Verifiers and CSPs **SHALL** require passwords that are used as a single-factor authentication mechanism to be a minimum of 15 characters in length."*

> *"Verifiers and CSPs **MAY** allow passwords that are only used as part of multi-factor authentication processes to be shorter but **SHALL** require them to be a minimum of eight characters in length."*

> *"Verifiers and CSPs **SHALL NOT** impose other composition rules (e.g., requiring mixtures of different character types) for passwords."*

> *"Verifiers and CSPs **SHALL NOT** require subscribers to change passwords periodically. However, verifiers **SHALL** force a change if there is evidence that the authenticator has been compromised."*

> *"Verifiers **SHALL** compare the prospective secret against a blocklist that contains known commonly used, expected, or compromised passwords."*

**Plugin compliance:**

- The `NIST_800_63B` preset sets `minLength = 15`, no composition (`cases = false`, `numbers = false`, `symbols = false`), no rotation (`expiryAmount = null`).
- HIBP-on-login + HIBP-at-change-time + `checkCommonPasswords = true` together satisfy the blocklist SHALL, compromised passwords (HIBP) and commonly-used passwords (bundled blocklist).
- HIBP-on-login matches trigger force-reset, satisfying "verifiers SHALL force a change if there is evidence that the authenticator has been compromised."

### §3.2.2: Rate-limiting

> *"The verifier **SHALL** limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100 by disabling that authenticator."*

The plugin delegates lockout to Craft core (`maxInvalidLogins`, default `5`, well under the ≤100 SHALL ceiling). The audit log captures lock/unlock events.

### Lite default vs the NIST minima

The plugin's **default `minLength = 6`** (Craft's own floor) sits below either NIST minimum, 15 for single-factor authentication and 8 for the password component of multi-factor authentication. Sites running on the default are NOT in NIST conformance; they're explicitly the "site picks its own floor" case. To reach NIST §3.1.1.2 SHALL on Lite without applying the Pro preset, hand-configure `minLength = 15` + `hibp = true` + `checkCommonPasswords = true` + composition rules off + no rotation. For MFA-component conformance, `minLength = 8` paired with Craft's own MFA when configured. The Pro `NIST_800_63B` preset bundles the single-factor field set as a one-click commitment.

This caveat is documented in [Edition Matrix → NIST 800-63B Rev. 4 alignment](../editions.md#nist-800-63b-rev-4-alignment).

### Other frameworks vs NIST Rev. 4

NIST Rev. 4 explicitly forbids composition rules and periodic rotation. PCI DSS v4.0.1 requires both. Don't try to satisfy both frameworks with one preset, pick the preset that matches your audit. The plugin supports both frameworks side-by-side via different preset selections.

## PCI DSS v4.0.1

**Payment Card Industry Data Security Standard, v4.0.1**

Published June 2024 as clarifications-only over v4.0. Future-dated requirements from v4.0 became mandatory on **31 March 2025**.

The plugin's `PCI_DSS_V4` preset addresses §8.3.x requirements; the Enterprise audit log addresses §10.x.

### §8.3.4: Account lockout

> *"After no more than 10 invalid attempts, an account is locked out. The lockout duration is at least 30 minutes or until the user's identity is verified."*

Delegated to Craft core (`maxInvalidLogins`, `cooldownDuration`). The default `5` invalid attempts and `300` seconds (5-minute) cooldown are within the §8.3.4 ceiling but not the 30-minute floor: operators may want to tune `cooldownDuration` to ≥1800 seconds (30 minutes) to align fully.

Document this delegation in your operator runbook: the plugin's audit log captures `account_locked` and `account_unlocked` events but the actual lockout enforcement is Craft's.

### §8.3.5: Breach-driven change

> *"Passwords/passphrases are immediately changed when any of the following occurs: a known compromise..."*

HIBP-on-login + force-reset is the literal implementation. The `BreachForced` audit reason on every breach-driven change provides the evidence trail.

### §8.3.6: Minimum length

> *"Passwords/passphrases are a minimum length of 12 characters (or IF the system does not support 12 characters, a minimum length of eight characters)."*

The `PCI_DSS_V4` preset sets `minLength = 12`. The "8 for legacy systems" carve-out doesn't apply: Craft 5 supports 12 trivially.

### §8.3.7: History

> *"Individuals cannot submit a new password/passphrase that is the same as any of the last four passwords/passphrases used."*

The `PCI_DSS_V4` preset sets `passwordHistoryCount = 4`, exact match.

### §8.3.9: Rotation

> *"Passwords/passphrases are changed at least once every 90 days, OR the security posture of accounts is dynamically analyzed..."*

The `PCI_DSS_V4` preset sets `expiryAmount = 90` / `expiryPeriod = day`, exact match on the conservative path.

> [!WARNING]
> **§8.3.9 conflicts with NIST 800-63B Rev. 4**
>
> NIST Rev. 4 explicitly forbids periodic rotation. PCI DSS requires it. Sites under PCI scope use the PCI preset; sites under NIST scope use the NIST preset. The two are mutually exclusive, pick the framework that matches your audit.

### §10.2: Audit log content requirements

> *"Audit logs capture: individual user access, admin actions, access to logs, invalid auth attempts, identification/auth mechanism use, account changes, log start/stop, system object creation/deletion."*

The Enterprise audit log captures `password_changed`, `password_reset_forced`, `account_locked`, `account_unlocked`, `hibp_breach_detected`, `hibp_check_failed`, `policy_changed`: the password-related subset of §10.2's required event categories.

For full §10.2 coverage you'll combine the plugin's audit log with Craft's own activity log and any application-level audit you've built.

### §10.3: Audit log integrity

> *"Audit logs are protected from destruction and unauthorized modification."*

The hash chain + verifier CLI is the literal implementation. The chain proves immutability post-write; the verifier proves the chain hasn't been tampered with after the fact.

### §10.5.1: Retention

> *"Retain audit log history for at least 12 months, with a minimum of three months immediately available."*

The plugin's default `auditLogRetentionDays = 365` satisfies the 12-month floor exactly. For longer retention, increase the setting + provision additional storage. For "immediately available": the audit log is queryable from the CP at all times within the retention window.

## CIS Controls v8

**Center for Internet Security Critical Security Controls v8 + CIS Password Policy Guide**

The plugin's `CIS_CONTROLS_V8` preset is built to satisfy Safeguard 5.2 (length floor) plus the CIS Password Policy Guide companion document (history, breach checking, blocklist, rotation). Verified against the CIS Controls Assessment Specification.

### Safeguard 5.2: Unique passwords

> *"Use unique passwords for all enterprise assets. Best practice implementation includes, at a minimum, an 8-character password for accounts using MFA and a 14-character password for accounts not using MFA."*

Applies to Implementation Groups IG1, IG2, IG3: every CIS adopter, not just enterprise tier.

The `CIS_CONTROLS_V8` preset sets `minLength = 14`. The plugin can't reliably detect MFA presence at preset-apply time, so the safer floor (14) is the default. Sites running Craft's native TOTP get a stricter-than-CIS-minimum policy, which CIS treats as conformant.

### CIS Password Policy Guide: companion recommendations

The Password Policy Guide adds:

- **History**: block reuse of the last 5 passwords. `passwordHistoryCount = 5` in the preset.
- **Breach checking**: continuously check passwords against a bad / banned / breached list. `hibp = true` in the preset.
- **Common-password blocklist**: at least 20 known poor or weak passwords. `checkCommonPasswords = true` in the preset (the bundled blocklist is well over 20 entries).
- **Rotation**: annual expiration plus forced rotation on suspected compromise. `expiryAmount = 365`, `expiryPeriod = 'day'` in the preset.
- **Length over complexity**: no required composition rules. `cases = false`, `numbers = false`, `symbols = false` in the preset.

### Edition

The one-click `CIS_CONTROLS_V8` preset apply lives under **Settings → Password Policy → Compliance Presets**, gated to Pro. Every preset field maps to a universally-shippable setting, so Lite operators can hand-configure the same field set; the Pro tier is where the framework-named one-click commitment lives, alongside per-group policy resolution.

### Other frameworks vs CIS

CIS's 365-day rotation deliberately diverges from NIST 800-63B Rev. 4 (which forbids periodic rotation). Sites aligning to CIS (typical CIS Benchmark shops, US federal contractors using CIS as the actionable companion to NIST) expect annual rotation. Sites aligning to NIST should NOT also apply the CIS preset; pick one framework per site.

## ISO/IEC 27001:2022

**ISO/IEC 27001:2022, Information Security Management Systems**

The Annex A controls reference ISO/IEC 27002:2022 for implementation guidance. Most controls relevant to password policy live under section 5 (Organizational) and section 8 (Technological).

### A.5.15 Access control

> *"Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements."*

Per-group named policies are the implementation: each policy is the rule-set for a different access-control segment.

### A.5.17 Authentication information

> *"Authentication information shall be controlled through a management process, including advising personnel on appropriate handling."*

Password lifecycle, history, blocklist, secure storage: the whole password-policy surface.

### A.5.33 Protection of records

> *"Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release."*

The hash chain + verifier + `CRAFT_AUDIT_PII_KEY` rotation provide the integrity, immutability, and access-control layers required by A.5.33. The retention purge mechanism handles the disposal side of "records protection."

### A.5.37 Documented operating procedures

> *"Operating procedures for information processing facilities shall be documented and made available to personnel who need them."*

The policy-change diff on every Pro named-policy save (Enterprise audit) is the literal change-evidence A.5.37 expects: every policy modification has a timestamped, attributed record of what changed.

### A.8.5 Secure authentication

> *"Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control."*

Front-end Twig builders (a11y-baked, AJAX-validated, elevated-session-aware), force-reset surfaces, rate-limited login (Craft core), and the audit trail of every auth-related action.

### A.8.15 Logging

> *"Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analyzed."*

**The single most directly applicable control for the plugin's audit log.** A.8.15 is what an ISO auditor will ask about when they ask "show me your access-event logging."

### A.8.16 Monitoring activities

> *"Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents."*

SIEM forwarder + webhook delivery + alert cooldowns are the operator surface that connects A.8.15 logs to A.8.16 monitoring.

## SOC 2

**AICPA Trust Services Criteria 2017 + 2022 Revised Points of Focus**

The TSC has not been re-issued since 2017. The 2022 update revised the *points of focus* (auditor guidance for evaluating each criterion) but not the criteria themselves. The 2017 numbering remains current.

### CC6.1 Logical access security

> *"The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives."*

Password policy enforcement, authentication, password storage. The bulk of the plugin's surface lands here.

### CC6.3 Access provisioning/de-provisioning

> *"The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets..."*

Force-reset actions, group-based policy assignment, retention CASCADE on user delete (`SET NULL` on `userId` preserves audit trail while removing live reference).

### CC6.7 Transmission of credentials

> *"The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes..."*

HIBP k-anonymity transmission (only the first 5 chars of SHA-1 leave the server), TLS verification enforced at the request site, HMAC-signed webhook delivery.

### CC7.2 System monitoring + anomaly detection

> *"The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts..."*

Audit log + SIEM forwarder + alert cooldowns + webhook delivery. The compliance dashboard is the operator-facing surface for CC7.2 monitoring.

### CC8.1 Change management evidence

> *"The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures..."*

Policy-change diffs on every Pro named-policy save: the literal change-evidence CC8.1 expects.

## GDPR

**Regulation (EU) 2016/679**

The relevant articles for password-policy + audit measures.

### Article 5(1)(f): Integrity and confidentiality

> *"Personal data shall be processed in a manner that ensures appropriate security of the personal data, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage..."*

HMAC `userIdentifier` (the audit log carries no email addresses; only hashes), SHA-256 `ipHash` (no raw IPs), per-event PII allowlist (fail-closed), retention CASCADE on user delete.

### Article 17: Right to erasure

> *"The data subject shall have the right to obtain from the controller the erasure of personal data concerning him or her..."*

The `SET NULL` on user hard-delete combined with the HMAC `userIdentifier` pattern lets controllers prove Article 17 was honoured without destroying the audit trail. A deleted user's audit history remains correlatable only to an auditor who retains the audit-PII key, and the controller can rotate the key (`./craft password-policy/audit/generate-pii-key --force`) to destroy that correlation entirely.

### Article 25: Data protection by design and by default

> *"Taking into account the state of the art, the cost of implementation and the nature, scope, context and purposes of processing as well as the risks of varying likelihood and severity for rights and freedoms..."*

The plugin's design choices are textbook Article 25 evidence:

- HMAC `userIdentifier` instead of plaintext email.
- Dedicated `CRAFT_AUDIT_PII_KEY` independent of `securityKey` (rotation without breaking sessions).
- Per-event PII allowlist (fail-closed).
- IP hashing instead of raw IP storage.
- User-Agent string explicitly dropped.

### Article 32(1)(b): Ongoing confidentiality, integrity, availability

> *"The controller and the processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, including inter alia as appropriate: the ability to ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services..."*

The hash chain + retention model + audit infrastructure as a whole.

### Article 32(1)(d): Regular testing

> *"...a process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures for ensuring the security of the processing."*

The independent verifier CLI is the literal implementation. The plugin provides the *capability*; you demonstrate the *process* by running the verifier on a schedule and retaining the output as evidence. The capability on its own does not satisfy Article 32, and the retained verifier output is what an auditor will ask to see.

### Article 30: NOT applicable

Article 30 is the controller's *register of processing activities*: a meta-document describing what processing the controller performs. It's not transactional audit logs. **Do not cite Article 30 for the plugin's audit log.** Auditors read it literally and bounce.

## Evidence package recipes

Three workflows for assembling evidence:

### Annual NIS2 / ISO 27001 audit pull

1. Export the past 12 months of audit log: **Utilities → Audit Export**, range `Last 365 days`, format JSONL.
2. Run the verifier: `./craft password-policy/audit/verify --json > verify-2026.json`.
3. Export the compliance dashboard's three reports: `audit-summary`, `alert-activity`, `retention-projection`. Print to PDF.
4. Combined package: JSONL audit + verifier JSON + three report PDFs + plugin source from GitHub. Hand to auditor.

### Quarterly SOC 2 evidence

1. Pull retention-projection report monthly: `password-policy/reports/retention-projection/csv`. Archive each.
2. Run verifier monthly: `password-policy/audit/verify --json`. Archive each JSON.
3. SIEM forwarder is the live monitoring evidence: your existing SIEM retention covers CC7.2.

### PCI DSS quarterly

1. Confirm preset is `PCI_DSS_V4` and `auditLogRetentionDays >= 365`.
2. Run verifier quarterly: archive output as §10.3 evidence.
3. Export audit log per QSA's date range.

## See also

- [Audit logging](../features/audit-logging.md): what's captured + privacy guarantees.
- [Audit verifier](../features/audit-verifier.md): the verifier CLI.
- [Audit export](../features/audit-export.md): evidence package workflows.
- [Compliance Dashboard](../features/compliance-dashboard.md): operator dashboard for monitoring.
- [Edition Matrix](../editions.md): what each tier ships, with framework anchors.
