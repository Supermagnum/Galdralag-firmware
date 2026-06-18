## 1. Purpose and scope

This document specifies a **Galdralag Web of Trust key registry server**: a standalone Rust HTTP service that stores OpenPGP public keys contributed by maintainers and users of Galdralag hardware, plus **sidecar metadata** (name, optional amateur-radio fields, optional **national society / club affiliation**, and optional **postal-location hints**) not defined by the OpenPGP User ID packet itself. The server anchors **claimed identity** to a fingerprint and validated email; it does **not** assign OpenPGP ownertrust, does **not** replace a general-purpose federated keyserver, and performs **no** secret-key or signing operations beyond verifying what submitters supply (certificate structure, algorithms, revocation signatures). Users extend trust through in-person verification and certificate signatures as described in the [Web of Trust and Key Signing Parties](README.md#web-of-trust-and-key-signing-parties) section of this repository’s README.

The first registry identity is intended to be the **hardware maintainer**, registered after Baochip-1x hardware is available for on-device key generation.

---

## 2. Relationship to Hagrid

**[Hagrid](https://gitlab.com/sequoia-pgp/hagrid)** (`gitlab.com/sequoia-pgp/hagrid`) is the verifying OpenPGP keyserver that powers `keys.openpgp.org`. It is written in Rust, uses **`sequoia-openpgp`** for certificate parsing and validation, and already provides patterns (and production code) for:

- ASCII-armored key upload and validation
- Email-based challenge–response consent (proof of control over the User ID address)
- Revocation certificate handling
- Lookup by fingerprint and email
- Privacy-oriented handling of identity material (GDPR-aligned design)

This Galdralag server is specified to **reuse Hagrid’s OpenPGP and mail-validation ideas and, where licence and maintenance allow, concrete code paths** (for example under `src/database/`, `src/mail.rs`, and the Sequoia import pipeline) instead of reinventing certificate handling. Planned divergences from upstream Hagrid:

| Area | Hagrid | Galdralag registry server |
|------|--------|---------------------------|
| Web framework | Rocket | **Axum** (native `tower` / `tower-http` layering) |
| Key storage | Files on disk; often fronted by nginx | **SQLx + SQLite** (single file): armored key + sidecar columns |
| Templates | Tera | **MiniJinja** (Jinja2 syntax; templates can be ported mechanically) |
| Outbound mail | Custom integration | **`lettre`** (async + rustls) |
| Metadata | Certificate-only | Extra table fields: callsign, DMR ID, optional **radio society / amateur group** text, optional **postal-location hints** (street, country, postal code, region) |

**Licence.** Hagrid is **AGPL-3.0**. Before vendoring or copying Hagrid sources into this workspace, review licence compatibility with this project’s **GPL-3.0** distribution. If combining AGPL and GPL-3.0 code in one binary is not acceptable for a given deployment, restrict reuse to **LGPL-2.0+ Sequoia crates** and re-implement only the thin coordination layer (upload parsing, confirmation state machine, HTTP handlers) without Hagrid verbatim.

---

## 3. Identity fields

Every submission is tied to one OpenPGP certificate (public key material only) and a **metadata record** keyed by primary **fingerprint**. The following fields apply. **Amateur radio callsign**, **DMR ID**, **radio affiliation**, and **postal hint** columns are **optional**; identity name and email behave as stated below (**email** ties to validated mailbox consent).

| Field | Required | Validation |
|-------|----------|------------|
| First name | Yes | Non-empty string, maximum 64 Unicode scalars (store as UTF-8; validate length after normalisation policy is fixed in code) |
| Last name | Yes | Non-empty string, same length bound as first name |
| Email address | Yes | RFC-like check via `validator`; must match at least one User ID email in the submitted certificate (case-insensitive comparison) |
| Amateur radio callsign | No | ICAO-style token (e.g. `LA1BC`); stored as submitted; no online registry query in v1 |
| DMR ID number | No | Unsigned 32-bit integer (when set, meaningful range **1–16777215** to align with amateur **DMR** practice). Meaningful mainly when a callsign is also present. |
| Radio amateur affiliation | No | Free text, maximum **128** Unicode scalars. Examples: **`NRRL`** (Norwegian Radio Relay League — *Norsk Radio Relæ Liga*); other national society abbreviations (**ARRL**, **RSGB**, **DARC**, **REF**, …); or **local amateur radio club / contest group** names. Not verified against registries in v1 — submitter-declared metadata only. |
| Street | No | UTF-8, maximum **512** scalars submitter-declared mailing / meeting address line; **not** verified against postal services |
| Country | No | UTF-8, maximum **128** scalars — country **name**, **abbreviation**, or similar submitter-declared label |
| Postal code | No | UTF-8, maximum **32** scalars (ZIP, postcode component, …) |
| Region | No | UTF-8, maximum **128** scalars — state, province, county, or similar subdivisions submitter-declared |

**DMR ID** is a globally unique numeric identifier allocated through RadioID-linked practice to licensed amateur operators across interconnected **DMR** systems; it is **not** an OpenPGP concept and is stored only in the sidecar table.

---

## 4. Crate inventory

| Crate | Minimum version (policy) | Role | Notes |
|-------|--------------------------|------|-------|
| `sequoia-openpgp` | `1.x` at implementation time | Parse `Cert`, extract fingerprint, validate User IDs, verify revocation material | Same core as Hagrid and `sq`; pin exact version in `Cargo.lock` |
| `axum` | `0.7+` | HTTP router and extractors | Replaces Rocket |
| `axum-server` | `0.7+` | TLS termination (rustls) for Axum | HTTPS listener |
| `tower` | `0.5+` | Composable service stack | Rate limit, timeout layers |
| `tower-http` | `0.5+` | Trace, compression, redirect | HTTP → HTTPS redirect middleware |
| `sqlx` | `0.8+` | Async SQL | Features: `sqlite`, `runtime-tokio-rustls`, `chrono`, `uuid` |
| `tokio` | `1.x` | Async runtime | Features: `full` (trim in production if desired) |
| `serde` / `serde_json` | `1.x` | Config and JSON API | |
| `lettre` | `0.11+` | SMTP | Features: `tokio1`, `tokio1-rustls-tls` |
| `minijinja` | `2.x` | HTML rendering | Port Hagrid/Tera templates incrementally |
| `uuid` | `1.x` | URL-safe opaque identifiers | Prefer **random 256-bit hex** (`token` column); optional for non-confirm IDs |
| `chrono` | `0.4+` | Timestamps | Features: `serde` |
| `tracing` | `0.1+` | Instrumentation | |
| `tracing-subscriber` | `0.3+` | Subscribers (JSON logs) | |
| `anyhow` | `1.x` | Error propagation in binaries | |
| `dotenvy` | `0.15+` | Load `.env` | |
| `governor` | `0.6+` | Token-bucket rate limiting | Expose as `tower` layer |
| `validator` | `0.18+` | Struct/field validation | Email, length, integer range |

Exact minimum patch versions are established when the crate is added to the workspace; the table states **policy** (major line) to avoid stale pins in this document.

---

## 5. Project layout

The **`galdralag-keyserver/`** crate is **not** a member of the **Galdralag-firmware** workspace **`Cargo.toml` today**—this layout defines how to add it (separate workspace member or sibling repo).

```text
galdralag-keyserver/
├── Cargo.toml
├── .env.example
├── migrations/
│   ├── 001_keys.sql
│   ├── 002_pending.sql
│   ├── 003_radio_affiliation.sql       -- ALTER only: DBs deployed before affiliation column existed
│   └── 004_postal_sidecar.sql         -- ALTER only: postal hint columns when absent from 001 revisions
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── submit.html
│   ├── revoke.html
│   ├── key_detail.html
│   ├── key_list.html
│   ├── confirm.html      # shown after clicking confirmation link
│   ├── rejected.html
│   └── email/
│       └── new_key_notification.txt
├── src/
│   ├── main.rs           # Axum router, AppState, server startup
│   ├── config.rs         # Config struct loaded from environment
│   ├── db.rs             # SQLx pool setup, migration runner
│   ├── models.rs         # KeyRecord, PendingSubmission structs
│   ├── openpgp.rs        # Sequoia-based cert parsing (adapted from Hagrid patterns)
│   ├── mail.rs           # lettre-based email sending
│   ├── handlers/
│   │   ├── web.rs        # GET handlers: index, list, detail, forms
│   │   ├── submit.rs     # POST /submit (web form) and POST /api/v1/keys
│   │   ├── revoke.rs     # POST /revoke (web form) and POST /api/v1/keys/revoke
│   │   └── confirm.rs    # GET /confirm/<token> and GET /reject/<token>
│   └── rate_limit.rs     # governor layer configuration
```

---

## 6. Database schema

**`migrations/001_keys.sql`**

```sql
CREATE TABLE IF NOT EXISTS keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint     TEXT    NOT NULL UNIQUE,           -- 40-char uppercase hex
    armored_key     TEXT    NOT NULL,                  -- ASCII-armored public key block
    first_name      TEXT    NOT NULL,
    last_name       TEXT    NOT NULL,
    email           TEXT    NOT NULL,
    callsign        TEXT,                              -- NULL if not provided
    dmr_id          INTEGER,                           -- NULL if not provided
    radio_affiliation TEXT,                          -- NULL; NRRL / club / national society etc.
    street              TEXT,
    country             TEXT,
    postal_code         TEXT,
    region              TEXT,
    submitted_at        TEXT    NOT NULL,              -- ISO 8601
    revoked_at      TEXT,                              -- NULL if active
    revocation_reason TEXT,                            -- NULL if active
    status          TEXT    NOT NULL DEFAULT 'active'  -- 'active' | 'revoked'
);

CREATE INDEX IF NOT EXISTS idx_keys_email       ON keys(email);
CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_keys_callsign    ON keys(callsign);
CREATE INDEX IF NOT EXISTS idx_keys_dmr_id      ON keys(dmr_id);
```

**`migrations/002_pending.sql`**

```sql
CREATE TABLE IF NOT EXISTS pending_submissions (
    token           TEXT    PRIMARY KEY,               -- 256-bit random hex, used in confirm/reject URLs
    new_fingerprint TEXT    NOT NULL,
    email           TEXT    NOT NULL,                  -- identifies the existing identity
    first_name      TEXT    NOT NULL,
    last_name       TEXT    NOT NULL,
    callsign        TEXT,
    dmr_id          INTEGER,
    radio_affiliation TEXT,
    street           TEXT,
    country          TEXT,
    postal_code      TEXT,
    region           TEXT,
    armored_key     TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL                   -- ISO 8601; discard after 72 hours
);
```

**`migrations/003_radio_affiliation.sql`** (run once on SQLite files created from **`001`** / **`002`** revisions that **omit** `radio_affiliation`; skip on fresh installs that already embed the column in **`001`** / **`002`** above.)

```sql
ALTER TABLE keys ADD COLUMN radio_affiliation TEXT;
ALTER TABLE pending_submissions ADD COLUMN radio_affiliation TEXT;
```

**`migrations/004_postal_sidecar.sql`** (run once on SQLite files whose **`001`** / **`002`** / **`003`** revisions omit **postal hint** columns.)

```sql
ALTER TABLE keys ADD COLUMN street TEXT;
ALTER TABLE keys ADD COLUMN country TEXT;
ALTER TABLE keys ADD COLUMN postal_code TEXT;
ALTER TABLE keys ADD COLUMN region TEXT;

ALTER TABLE pending_submissions ADD COLUMN street TEXT;
ALTER TABLE pending_submissions ADD COLUMN country TEXT;
ALTER TABLE pending_submissions ADD COLUMN postal_code TEXT;
ALTER TABLE pending_submissions ADD COLUMN region TEXT;
```

---

## 7. Submission methods

### 7a. Web form (`POST /submit`)

The site serves **`GET /submit`** with an HTML form. Fields: mandatory name and email, optional **callsign**, **DMR ID**, **radio affiliation**, optional **street / country / postal code / region** (leave blank when unused), plus a `<textarea>` for the ASCII-armored public key block. **`POST /submit`** runs:

1. `validator`-based checks on typed fields (lengths, optional **DMR id** numeric range aligned with §3, optional **affiliation** and **postal** column bounds, email format).
2. Parse armored data in `openpgp.rs` with Sequoia; reject malformed packets or cryptographic validation failures surfaced by the library.
3. Require that the submitted email matches **at least one** `UserID::email()` in the certificate (case-insensitive normalisation).
4. Enforce the algorithm allowlist (section 9).
5. If the fingerprint exists in `keys` with `status = 'active'` and material is an exact duplicate policy allows: treat as **idempotent success** (no duplicate rows), show confirmation.
6. If the email exists on an **`active`** row with a **different** fingerprint: run the duplicate-identity workflow (section 8); **do not** insert into `keys` yet.
7. Otherwise: insert a new `keys` row and show confirmation.

Implementation note: tighten “exact duplicate” to mean **same fingerprint and same stored armored text** (or normalised armour) so accidental re-upload does not churn metadata.

### 7b. JSON API (`POST /api/v1/keys`)

Supports automation (e.g. **`galdra keyserver push`**). Same validation and branching as §7a.

Request body:

```json
{
  "first_name": "Ola",
  "last_name":  "Nordmann",
  "email":      "ola@example.com",
  "callsign":   "LA1BC",
  "dmr_id":     2345678,
  "radio_affiliation": "NRRL",
  "street": "Example gate 1",
  "country": "NO",
  "postal_code": "0154",
  "region": "Oslo",
  "armored_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
}
```

Optional sidecar columns **`callsign`**, **`dmr_id`**, **`radio_affiliation`**, **`street`**, **`country`**, **`postal_code`**, and **`region`** may be omitted or JSON `null`.

Responses:

Success (`200 OK`):

```json
{ "status": "accepted", "fingerprint": "AABBCCDD..." }
```

Duplicate identity pending email (`202 Accepted`):

```json
{ "status": "pending_confirmation", "message": "Confirmation email sent to address on file." }
```

Validation error (`422 Unprocessable Entity`):

```json
{ "status": "error", "reason": "Key algorithm not in allowlist: DSA" }
```

### 7c. Revocation — web form (`POST /revoke`)

User pastes an ASCII-armored **revocation certificate** (or armored artefact carrying a verified revocation Sequoia accepts—exact armour type is fixed in implementation). Handler:

1. Parse with Sequoia.
2. Resolve issuer fingerprint; look up matching row in `keys`.
3. Verify revocation cryptographically against the stored certificate.
4. Set `status = 'revoked'`, `revoked_at` to current ISO8601, `revocation_reason` from packet if present; else SQL `NULL`.

### 7d. Revocation — JSON API (`POST /api/v1/keys/revoke`)

```json
{
  "email": "ola@example.com",
  "armored_revocation_cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
}
```

The **`email`** field ties the submission to operational logging and abuse monitoring; revocation validity is still cryptographic. Pipeline matches §7c.

---

## 8. Duplicate identity flow

When **`email`** matches an existing **`active`** key but **`fingerprint`** differs:

1. Generate a cryptographically secure **256-bit** random value; encode as **64 hex digits**; use as **`token`** in **`pending_submissions`** with **`expires_at = now + 72 hours`** (ISO8601).
2. Email the **currently registered address** (`lettre`): show old fingerprint, new fingerprint, submitted **radio affiliation** and **postal hints** when present (if any), and links `{KEYSERVER_BASE_URL}/confirm/{token}` and `{KEYSERVER_BASE_URL}/reject/{token}`.
3. Respond to API clients with **`pending_confirmation`** (HTTP 202).

Confirmation:

- **`GET /confirm/{token}`**: valid, non-expired row → revoke old key (`revoked_at`, **`revocation_reason = 'superseded'`**), insert new **`active`** key with submitted metadata and armour, delete pending row, render **`confirm.html`**.

Rejection:

- **`GET /reject/{token}`**: delete pending row, render **`rejected.html`**; registered key unchanged.

Housekeeping:

- On startup spawn `tokio::spawn` periodic task (**hourly**): `DELETE FROM pending_submissions WHERE expires_at < datetime('now')` (SQLite) or equivalent.

If the registrant **no longer controls** the mailbox, replacement under the same email is blocked until the **old** key is revoked with a valid revocation certificate; the duplicate flow intentionally sends mail **only** to the address already on file.

---

## 9. Key validation rules

- Armour decodes to a parseable **`sequoia_openpgp::Cert`**.
- At least one User ID with **`UserID::email()`** matching the submitted email (case-insensitive).
- **Algorithm allowlist** (reject others with explicit reason): Ed25519, X25519, Brainpool **P-256r1 / P-384r1 / P-512r1**, NIST **P-256 / P-384**, RSA **≥ 2048** bit keys. Inspect primary key and relevant subkeys per policy written in code (mirror Galdralag device capabilities where practical).
- Reject certs that already carry a verified **self-revocation** affecting the submitted key material.
- **Exact fingerprint duplicate**: idempotent acceptance (§7a step 5).
- **Maximum** armoured upload size **128 KiB**; enforce in Axum body limit before parsing.

---

## 10. Web interface routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Landing: project scope, README cross-links, WoT expectation |
| `GET` | `/keys` | Paginated list: name, optional callsign / DMR / **radio affiliation** / **postal hints**, fingerprint, submitted date, status |
| `GET` | `/keys/{fingerprint}` | Detail page: metadata including optional **radio affiliation** and **postal** columns, armour block, revocation info when applicable |
| `GET` | `/submit` | Submission form |
| `POST` | `/submit` | Process form POST |
| `GET` | `/revoke` | Revocation paste form |
| `POST` | `/revoke` | Process revocation |
| `GET` | `/confirm/{token}` | Approve superseding key |
| `GET` | `/reject/{token}` | Decline superseding key |
| `POST` | `/api/v1/keys` | JSON submit |
| `POST` | `/api/v1/keys/revoke` | JSON revoke |

Fingerprint in paths is **normalized** uppercase hex **without spaces** for stability.

---

## 11. `galdra keyserver push` integration

**Status.** This section is specification only: the **`keyserver`** config table and **`galdra keyserver push`** CLI are **not** implemented in the current **`galdra`** / **`galdra-core-host`** tree. Today's host config (`galdra-core-host/src/config.rs`) exposes **`[keyservers]`** (`servers`, `timeout_seconds`) for **HKP fetch** (`galdra contact fetch --source keyserver`), which is unrelated to the registry **`url`** below.

Once implemented, **`galdra keyserver push`** should:

1. Resolve the registry **`url`** from, in order: environment **`GALDRA_KEYSERVER_URL`**, then **`[keyserver].url`** in the same **`config.toml`** file **`galdra` already loads** (`--config PATH` overrides; otherwise **`galdra_core_host::config::default_config_path()`**: **Linux / generic Unix** → **`~/.config/galdra/config.toml`**; **macOS** → **`~/Library/Application Support/galdra/config.toml`**; **Windows** → **`%APPDATA%\galdra\config.toml`**).
2. Export the **public** OpenPGP certificate from the connected token using the documented card export paths in [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md).
3. Collect **first name**, **last name**, optional **callsign**, optional **DMR ID**, optional **radio affiliation**, optional **`street` / `country` / `postal_code` / `region`** (TTY prompts or CLI flags—exact UX matches whatever **`galdra`** uses elsewhere). Derive **email** **only** from **`User ID`** packets on the exported cert (**reject** if missing or if multiple mails make the choice ambiguous without an explicit flag).
4. **`POST`** to **`{base_url}/api/v1/keys`** with JSON as in §7b (`Content-Type: application/json`).
5. Print server JSON (**stdout**) for scripting; non-zero exit on **`4xx`** / **`5xx`**.

Implementers extend **`serde`** deserialization in **`Config`** with an optional **`[keyserver]`** section so existing installs without it keep working.

```toml
[keyserver]
url = "https://keys.example.com"
```

Landing this subcommand is expected **after** the standalone **`galdralag-keyserver`** binary crate exists (**not** a member of the firmware workspace **`Cargo.toml` until added).

---

## 12. Configuration (environment variables)

```bash
DATABASE_URL=sqlite:./keyserver.db
KEYSERVER_BASE_URL=https://keys.example.com
KEYSERVER_BIND=0.0.0.0:8443
KEYSERVER_TLS_CERT=/etc/ssl/keyserver.crt
KEYSERVER_TLS_KEY=/etc/ssl/keyserver.key
KEYSERVER_SMTP_HOST=smtp.example.com
KEYSERVER_SMTP_PORT=587
KEYSERVER_SMTP_USER=keyserver@example.com
KEYSERVER_SMTP_PASSWORD=secret
KEYSERVER_SMTP_FROM=keyserver@example.com
KEYSERVER_RATE_LIMIT_SUBMISSIONS=5          # max submissions per IP per hour
```

Load at startup via **`dotenvy::dotenv()`** (optional `.env`), then hydrate a **`serde`-deserializable `Config`** (stringly-typed env with `Deserialize` derives or explicit mapping).

---

## 13. Deployment

The service listens with **HTTPS** using **`axum-server`** + **rustls** and PEM paths from **`KEYSERVER_TLS_*`**. A **`tower-http`** redirect layer forces **HTTP → HTTPS** for cleartext listeners if any auxiliary socket exists.

This registry **does not** participate in **`keys.openpgp.org`** federation or SKS gossip; operators run it as **project-local** infrastructure.

The deployable artefact is a **single Rust binary**. **SQLite** is a normal file beside the binary or under a writable data directory—no separate database daemon.

Alternatively terminate TLS at **nginx** or **Caddy** and proxy to **Axum bound to localhost**; drop `axum-server` rustls paths in that mode.

Operational logs use **`tracing-subscriber`** (**JSON** output recommended for ingestion). **`governor`** enforces **`KEYSERVER_RATE_LIMIT_SUBMISSIONS`** per source IP per hour on **`POST /submit`** and **`POST /api/v1/keys`** (and optionally revocation POST endpoints if abuse warrants).

### SQLite storage estimate

Disk use is dominated by **`armored_key`** (ASCII public keys vary with algorithm and packet count); sidecar columns and indexes add a smaller baseline per row plus **SQLite** internals, **WAL**, and backups.

Rough model (not a promise): **`total ≈ N × (avg_armoured_length + ~1–2 KiB metadata) × (1.3–2.0)`** where the trailing factor stands in for indexes, page overhead, WAL, and headroom.

**Illustrative order of magnitude:** if **`N ≈ 5×10⁶`** registered rows and **~10 KiB** average armoured key material (plus metadata), the **database file alone** lands in the **~65–100 GiB** band before backups; RSA-heavy certs with large User ID sets push toward the **upper** end or beyond. Operators should **`VACUUM`**, monitor **`PRAGMA page_count`**, and provision **additional** disk for copies and WAL (often **≈0.5×–2×** reserve). Decimal **GB** vs binary **GiB** differ (**100 GiB ≈ 107 GB**).

This project-local registry expects **far fewer** submissions than worldwide licensee counts unless scope changes.

---

## 14. Future work (out of scope for initial implementation)

| Item | Notes |
|------|-------|
| WKD endpoint (RFC 9580) | Serve `/.well-known/openpgpkey/` for mailbox-based discovery |
| Optional upload to Hagrid | Forward confirmed keys via `keys.openpgp.org` upload API |
| Callsign verification | HTTP GET to **`https://www.radioid.net/api/dmr/user/?id={dmr_id}`** to correlate DMR ID and callsign |
| Governikus attestation badge | Surface third-party attestations parsed from cert if present |
| Admin UI | Manual removal, moderation, audit timeline |
| WoT graph | Visualisation of signatures among registered keys |
