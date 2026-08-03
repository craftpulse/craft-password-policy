# IP Geolocation

Resolves the country a login or password change came from, so an audit row and a new-device alert can say "a sign-in from Belgium" rather than just "a sign-in".

Off by default. Nothing is resolved and nothing is enriched until you turn it on.

## What it stores

**A two-letter country code. That is all.**

The raw IP is used for the lookup and then discarded. It is never written to the audit log, never written to the device table, and never logged. The audit log's own IP column stores a SHA-256 hash, which predates this feature and is unaffected by it.

The `geoRegion` column exists alongside `geoCountry` and is almost always null, because the bundled database is country-level. It is there so a future city-level database can populate it without a schema change.

This is a deliberately small amount of data. Geolocation from an IP is approximate at the best of times: a VPN, a corporate egress, or a mobile carrier's national gateway will all report somewhere the user is not. Treat a country code as a weak signal worth showing a user in an alert email, not as evidence.

## Turning it on

```
Settings → Password Policy → Audit → Enable IP geolocation
```

Or in `config/password-policy.php`:

```php
return [
    'geoIpEnabled' => true,
];
```

Two things must both be true for enrichment to actually run: the setting is on, **and** the edition is Enterprise. The `geoCountry` / `geoRegion` columns exist on every edition, because the plugin captures universally and gates the exposure, but nothing writes to them below Enterprise.

## What consumes it

- **Audit rows.** `geoCountry` is stored on the row. It is excluded from the hash chain, so enabling or disabling geolocation never invalidates an existing chain.
- **New-device alert emails.** The alert body gets a location hint alongside the device label. See [Device tracking](./device-tracking.md).

## Your obligations as an operator

This is the part to read before turning it on. Two of them are yours, not ours.

### 1. `geoip2/geoip2` is a hard requirement

The reader is the `geoip2/geoip2` Composer package, which sits in the plugin's `require` block rather than `suggest`. It is pure PHP: no PECL extension to install, no external API call at login time, no per-lookup latency beyond a memory-mapped file read.

Because it is a hard requirement, it is installed on your site whether or not you ever turn geolocation on. If your organisation reviews the dependency tree, this is one to know about rather than discover.

### 2. The bundled database is CC BY 4.0, and attribution is required

The plugin ships the **DB-IP IP-to-Country Lite** database, roughly 8 MB, at `src/data/geoip/dbip-country-lite.mmdb`. It is licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).

CC BY 4.0 requires attribution. **If you enable geolocation, you are using that database, and you must keep the attribution visible:**

```
IP Geolocation by DB-IP (https://db-ip.com)
```

The plugin surfaces this notice in the control panel's audit settings screen and in the plugin source. Do not remove it, and if you build your own screens that display geolocated data, carry the line through to them.

If you would rather not take on the attribution obligation, leave `geoIpEnabled` off. Everything else in the plugin works unchanged: audit rows are written without geo columns populated, and new-device alerts are sent without a location hint.

### 3. Refresh the database periodically

IP allocations move. A database shipped with a release goes stale, and a stale country lookup is worse than none because it is confidently wrong.

DB-IP publishes a fresh Lite database monthly. To refresh in place:

```shell
cd vendor/craftpulse/craft-password-policy/src/data/geoip
curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
  | gunzip > dbip-country-lite.mmdb
```

If the current month has not been published yet the URL 404s; fall back to the previous month. There is no code or schema change, and no cache to clear: the reader opens whatever file is at that path.

A refresh into `vendor/` is undone by the next `composer update`, which restores the database that shipped with the release. Put the refresh in your deploy pipeline, after the Composer step, so it survives.

## Failure behaviour

Every failure mode returns "no location available" and nothing more. The lookup never throws, and a geolocation problem can never break a login or drop an audit row.

That covers a missing or unreadable `.mmdb`, a private or reserved address (RFC 1918, loopback, link-local), a malformed address, an address the database does not know, and any internal error from the reader.

So during local development, where every request comes from a private address, geolocation resolves to nothing and the columns stay null. That is expected and not a misconfiguration.

## See also

- [Audit logging](./audit-logging.md): the rows the country code lands on.
- [Device tracking](./device-tracking.md): the alert that uses the location hint.
- [Database schema](../reference/database-schema.md): the `geoCountry` / `geoRegion` columns.
- [Compliance frameworks](../operations/compliance-frameworks.md): data-minimisation clauses relevant to enabling this.
