# Audit Verifier CLI (Enterprise)

The audit verifier is a console command that walks the hash chain row-by-row, recomputes each `rowHash`, compares against the stored value, and exits with a clear pass/fail status. It's the credibility multiplier on the hash chain: a chain with no public verifier is just marketing.

```bash
./craft password-policy/audit/verify
```

This page covers running the verifier, interpreting the output, the cron recipe for production, and the auditor-from-fresh-checkout workflow that turns the chain into a piece of evidence.

For the underlying chain mechanics, see [Audit logging](./audit-logging.md).

## Quick start

From your Craft project root:

```bash
./craft password-policy/audit/verify
```

Output on a healthy chain:

```
OK: 12,347 rows verified.
```

Exit code `0`. Done.

## Output

### Clean pass

```
OK: 12,347 rows verified.
```

Exit code `0`. The chain is intact; no row's `rowHash` deviates from the canonical SHA-256 of its payload plus the preceding row's hash.

### Chain break

```
FAILED at row id=8821 (dateCreated 2026-04-12T09:33:14Z)
    stored rowHash:   8e3a4f2d2c1b9e76a4f3...
    computed rowHash: c91d7a8b3e2f1d8e57a4...
    previous rowHash matched: yes
```

Exit code `1`. The verifier stops at the first break; re-run with `--from=<date>` after fixing or investigating to verify the rest of the chain.

Interpretation:

- `previous rowHash matched: yes`: every row up to this one verified clean. The break is at this specific row.
- `previous rowHash matched: no`: the chain was broken earlier; this row is the first one with a mismatching `previousHash`.

Either way: something modified the database outside the plugin's `AuditLogService::logEvent()` write path. Investigate the row, the surrounding rows, the database write timestamp, and the application-level audit (who had DB write access at the time).

### Unreadable row

```
ERROR: row id=4421 has malformed JSON in details column
```

Exit code `2`. A row's data is corrupt: the JSON column won't parse, datetime column has a non-canonical value, etc. The chain integrity is undetermined for that row.

This is almost always a sign of direct DB tampering or a backup-restore where the database state is partially incomplete.

## Flags

| Flag | Purpose |
|---|---|
| `--from=<date>` | Start verification from this date (ISO 8601 or `YYYY-MM-DD`). Useful for daily-incremental verification crons. |
| `--to=<date>` | Stop verification at this date. |
| `--json` | Emit machine-readable JSON output instead of the human-readable report. Designed for CI / monitoring pipelines. |
| `--verbose` | Print one line per verified row. Useful for debugging when the chain check is silent. |

### JSON output shape

```json
{
    "status": "ok",
    "verified": 12347,
    "from": null,
    "to": null,
    "duration_ms": 312
}
```

On break:

```json
{
    "status": "failed",
    "verified": 8820,
    "broke_at": {
        "id": 8821,
        "dateCreated": "2026-04-12T09:33:14Z",
        "stored_rowHash": "8e3a4f2d...",
        "computed_rowHash": "c91d7a8b...",
        "previous_rowHash_matched": true
    },
    "duration_ms": 244
}
```

Pipe to your monitoring stack:

```bash
./craft password-policy/audit/verify --json | jq -e '.status == "ok"'
```

`jq -e` exits non-zero on a falsy result, useful for shell-level alerting integration.

## Cron recipe

Run the verifier daily (incremental over the previous day's writes) to detect tampering within 24 hours.

```cron
# Verify yesterday's audit chain every morning at 03:00 local time
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --from=$(date -d yesterday +%Y-%m-%d) --to=$(date -d yesterday +%Y-%m-%d) --json | tee /var/log/pp-audit-verify.log
```

The non-zero exit code on failure is the alertable event. Forward `/var/log/pp-audit-verify.log` to your log aggregator, or pipe through your existing monitoring agent.

For monthly full-chain verification (catches retention purge artifacts, full history sweeps):

```cron
# Full audit-chain verification on the 1st of every month at 02:00
0 2 1 * * cd /path/to/project && ./craft password-policy/audit/verify --json | tee /var/log/pp-audit-verify-monthly.log
```

## Performance

The verifier reads raw `Query` cursors (not Craft element queries) so it doesn't pay the element-hydration cost. Typical performance:

- **10,000 rows**: sub-second on local SSD; 1-2 seconds on shared cloud DB.
- **100,000 rows**: 5-15 seconds depending on DB latency.
- **1,000,000+ rows**: measured in minutes. Use `--from` to incrementalize.

The hot loop is a SHA-256 recompute per row, CPU-bound after the DB fetch.

## Retention-purge tolerance

When the `password-policy/gc/run` retention purge hard-deletes rows that fall outside the configured window, the chain has gaps. The verifier handles this by recognising the gap as legitimate retention purge rather than tampering: it verifies the surviving rows among themselves and reports the gap as informational rather than as a chain break.

Specifically: the verifier reads `previousHash` from each row and looks up the matching `rowHash` from the most-recent earlier row that exists in the table. If no row matches (the previous row was retention-purged), the verifier checks that the `previousHash` matches a known-good ancestor in the gap.

This means a retention-purged chain still verifies. An attacker who tries to use "retention purge" as cover for tampering still breaks the chain: the verifier detects when a `previousHash` doesn't match any plausible ancestor.

## Permission

Running the verifier from a CP-authenticated console requires `pp:audit-verify`. The same command also runs without a CP user identity for the auditor-from-fresh-checkout case, see below.

## Auditor workflow: verifying from a fresh checkout

This is the workflow that turns the audit log into evidence rather than a claim. An auditor (third-party, internal compliance team, or your own future self) can:

1. **Clone the plugin's public GitHub repository.** The verifier source is in `src/console/controllers/AuditController.php`: no obfuscation, no minification, no compiled bytecode.
2. **Set up a Craft project pointing at your database.** Either a fresh staging clone with the production database restored, or a read-only DB user with `SELECT` access to `passwordpolicy_audit_log` and `craft_elements`.
3. **Run the verifier with `--json`.** The output proves chain integrity at the time of verification.
4. **Save the JSON output.** Combined with the database snapshot timestamp, it's a point-in-time attestation that the chain was intact.

The verifier code path is open source for exactly this reason. A hash chain that ships only as part of a paid Enterprise plugin would let buyers wonder whether the verifier itself is doing real cryptography or marketing theatre. The public repo + auditor-runnable workflow closes that gap.

## Limitations

The verifier proves cryptographic chain integrity at the time of verification. It does **not**:

- **Prove rows were written at the times their `dateCreated` columns claim.** A sophisticated attacker with DB-write access could fabricate a chain from scratch with backdated timestamps. The chain proves immutability post-write, not authenticity-of-time.
- **Catch tampering that doesn't break the chain.** Modifying `dateCreated` on a row in place breaks the chain. Modifying `details.deviceLabel` from `"Chrome"` to `"Safari"` breaks the chain. But adding a row at the top with a freshly-computed `rowHash` doesn't break the chain: the verifier sees an extra valid row.

For tamper detection beyond the chain itself, combine verification with:

- **External anchoring**: periodically hash the latest `rowHash` and submit it to a public timestamp authority (RFC 3161 TSA, S3 Object Lock, blockchain anchor). The plugin doesn't ship this.
- **SIEM forwarding**: see [SIEM forwarders](./siem-forwarders.md). Forwarded rows in a SIEM you don't control are tamper-resistant once received; the verifier's job is to prove the source-side chain hasn't been tampered with after the fact.
- **DB-level access controls**: restrict `INSERT/UPDATE/DELETE` on `passwordpolicy_audit_log` to the application user only. Audit DB privileges separately.

The chain + verifier is the proof-of-immutability layer. Other layers add proof-of-authenticity, proof-of-completeness, etc.

## See also

- [Audit logging](./audit-logging.md): what's captured, the hash chain mechanics, the privacy guarantees.
- [Compliance Dashboard](./compliance-dashboard.md): the Enterprise UI shows chain-health status via the verifier, with a 5-minute cache.
- [SIEM forwarders](./siem-forwarders.md): second copy of every audit row in your SIEM, for proof-of-completeness.
- [Compliance frameworks](../operations/compliance-frameworks.md): clause anchors for chain integrity evidence (PCI DSS §10.3, ISO 27002:2022 A.5.33, GDPR Art. 32(1)(d)).
