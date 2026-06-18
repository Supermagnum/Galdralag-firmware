# Galdra — Token Management Tool Specification

**Version:** 0.1 (draft)
**Date:** 2026-03-26
**Status:** Specification — host tools (`galdra`, `galdrad`, `galdra-gtk`) are implemented in-tree; behaviour may evolve until 1.0

---

## Table of Contents

- [Usage examples (quick start)](#usage-examples-quick-start)
- [Token keys, publishing, revocation, and deletion](#token-keys-publishing-revocation-and-deletion)
- [Purpose and scope](#purpose-and-scope)
- [Target user populations](#target-user-populations)
- [Architecture overview](#architecture-overview)
- [Tier 1 — Core library: `galdra-core-host`](#tier-1--core-library-galdra-core-host)
- [Tier 2a — CLI: `galdra`](#tier-2a--cli-galdra)
- [Tier 2b — Local daemon: `galdrad`](#tier-2b--local-daemon-galdrad)
- [Tier 2c — Desktop GUI (GTK4)](#tier-2c--desktop-gui-gtk4)
- [Build and installation](#build-and-installation)
- [Identity model](#identity-model)
- [Group model](#group-model)
- [Database schema](#database-schema)
- [Key fetching sources](#key-fetching-sources)
- [Multi-recipient encryption](#multi-recipient-encryption)
- [Offline operation](#offline-operation)
- [Audit logging](#audit-logging)
- [PIN attempt policy](#pin-attempt-policy)
- [Integration requirements](#integration-requirements)
- [Operational guide: keys and Shamir](#operational-guide-keys-and-shamir)
- [CLI command reference](#cli-command-reference)
- [Security requirements](#security-requirements)
- [Compliance considerations](#compliance-considerations)
- [Implementation status (original phased roadmap)](#implementation-status-original-phased-roadmap)
- [Dependencies](#dependencies)
- [Out of scope](#out-of-scope)

---

## Usage examples (quick start)

These examples use the **current** `galdra` CLI (long options such as `--input` / `--output`). Build the binaries from the repository (see [Build and installation](#build-and-installation)). The default SQLite database path follows the platform data directory unless you pass `--db`; optional config is loaded from the platform config path unless you pass `--config`.

**Discover flags:** `galdra --help` and `galdra <subcommand> --help` (for example `galdra encrypt --help`).

### Device

Check whether a token is visible and basic status:

```bash
galdra device status
```

If a token is connected and must be unlocked, use an interactive PIN prompt (never pass the PIN on the command line):

```bash
galdra device unlock
galdra device lock
```

### Contacts

Add a contact **without** importing a key (metadata only). **`--email` is required**; optional **`--name`** (display name), **`--fluxer-id`**, **`--discord-id`**, **`--irc-id`**, **`--callsign`**, and other flags follow the same rules as in the [identity model](#identity-model).

```bash
galdra contact add --email ops@example.org --name "Example station" --callsign W1ABC \
  --street "Karl Johans gate 1" --postal-code 0154 --region Oslo --country NO --dmr-id 2412345 \
  --radio-affiliation NRRL --fluxer-id my-handle --discord-id "123456789012345678" --irc-id "nick"
```

Optional **postal hints** (`--street`, `--country`, `--postal-code`, `--region`) are stored in the local SQLite contact row only (not authenticated; omit them if you prefer least data). Amateur-radio fields **`--dmr-id`** (1–16777215) and **`--radio-affiliation`** (max 128 characters) behave the same way.

Import an OpenPGP public key from a file:

```bash
galdra contact import --file alice.pub.asc
```

Fetch a key from a keyserver (uses `[keyservers]` in `config.toml` unless you pass `--server`):

```bash
galdra contact fetch "alice@example.org" --source keyserver
```

Fetch via Web Key Directory (WKD) using an email address:

```bash
galdra contact fetch "alice@example.org" --source wkd
```

List contacts:

```bash
galdra contact list
```

### Groups and multi-recipient encryption (OpenPGP)

Create a group and add members by identifier (contact **id**, **callsign**, **e-mail**, **Fluxer id**, **Discord id**, or **IRC id** as stored in the database):

```bash
galdra group create net_control --description "Net control operators"
galdra group add net_control W1ABC K2XYZ
```

Copy members from another group:

```bash
galdra group add emergency_all --from-group net_control
galdra group add emergency_all --from-group region_east
```

Encrypt a file to **all current, non-expired** members of a group. The default format is OpenPGP (`--format openpgp`):

```bash
galdra encrypt --input message.txt --output message.txt.gpg --group net_control
```

Encrypt to explicit recipients (repeat `--to` for multiple contacts):

```bash
galdra encrypt --input message.txt --output message.txt.gpg --to W1ABC --to K2XYZ
```

Abort if any recipient key is missing or expired:

```bash
galdra encrypt --input message.txt --output message.txt.gpg --group net_control --strict
```

Decrypt OpenPGP ciphertext. You must pass **`--recipient`** with a contact identifier (**id**, **callsign**, **e-mail**, **Fluxer id**, **Discord id**, or **IRC id**) so the tool can load the right public certificate material for parsing. Full private-key decryption on the host is not implemented; production use expects a connected token where firmware support exists:

```bash
galdra decrypt --input message.txt.gpg --output message.txt --recipient W1ABC
```

### age format (optional)

When you do not need OpenPGP compatibility, use age. Pass one `--age-recipient` per recipient public key:

```bash
galdra encrypt --format age --input message.txt --output message.txt.age --age-recipient age1example...
```

Decrypt age ciphertext with an identity file (private key material for age):

```bash
galdra decrypt --format age --input message.txt.age --output message.txt --age-identity /path/to/age-identity.txt
```

### Sync and audit

Export and import the **public** contact and group database for offline handoff (no private keys):

```bash
galdra sync export --output galdra-sync.db
galdra sync import --input galdra-sync.db --merge
```

Use `--replace` instead of `--merge` only when you intend to replace the local database (dangerous).

Show recent audit entries and verify the append-only hash chain:

```bash
galdra audit show --limit 50
galdra audit verify
```

### Local daemon `galdrad` (HTTP on localhost)

`galdrad` serves a JSON REST API over **HTTP** on **127.0.0.1:8742** by default. Override the bind address with `--listen` if needed.

```bash
galdrad
```

```bash
curl -s http://127.0.0.1:8742/health
```

Interactive API documentation is available in the running process at **http://127.0.0.1:8742/swagger-ui/** (OpenAPI JSON at `/api-docs/openapi.json`). Some crypto endpoints may still return stubs until fully wired to the token.

### Desktop GUI `galdra-gtk`

The GTK4 client talks to `galdrad` over HTTP. The base URL defaults to `http://127.0.0.1:8742` and can be set with `--base-url` or the **`GALDRAD_URL`** environment variable:

```bash
GALDRAD_URL=http://127.0.0.1:8742 galdra-gtk
```

### What may still be incomplete

Token-specific flows (`galdra key generate`, `galdra sign`, decrypt/sign paths that require firmware support) may return errors until device integration matches your firmware build. Prefer `galdra … --help` and release notes over this document when behaviour diverges.

---

## Token keys, publishing, revocation, and deletion

This section answers: **how you create keys on the token**, **how you delete keys** (contacts, token slots, or the whole device), **how you revoke OpenPGP certificates**, and **how you export and publish public keys** so others can fetch them. It complements [Usage examples (quick start)](#usage-examples-quick-start).

### Mental model

| Material | Where it lives |
|----------|----------------|
| **Private keys** | On the Galdralag token only. The host SQLite database never stores private key bytes. |
| **Your public key** | Produced by exporting from a token slot (`galdra key export`) or by using another tool (for example GnuPG) and optionally importing to the token later. |
| **Other people’s public keys** | Stored as **contacts** in the local database; retrieved with `galdra contact fetch` / `import`, not by uploading your own key. |

### Create keys on the token

1. Connect the token and unlock if required (`galdra device status`, `galdra device unlock`).
2. Initialise a blank token if needed (`galdra device provision`; follow prompts and product documentation).
3. Generate a key pair **in a token slot** (private key never leaves the device):

```bash
galdra key list
galdra key generate --type ed25519
```

Supported `--type` values are documented in `galdra key generate --help` (for example `brainpool256`, `brainpool384`, `brainpool512`, `rsa2048`, `rsa4096`, `ed25519`).

**Current limitation:** `galdra key generate` and `galdra key import` return an error until host-to-device key provisioning is fully integrated for your firmware build. Until then, generate keys with **GnuPG** on the host (`gpg --full-generate-key`) or your organisation’s process, then plan to load material onto the token when import is available, per firmware documentation.

### Export your public key (file or stdout)

Export the **public** half of a key from slot `N` as OpenPGP (default), PEM, or DER. Output goes to **stdout**; redirect to a file for publishing:

```bash
galdra key export --slot 1 --format pgp > my_pubkey.asc
galdra key export --slot 1 --format pem > my_pubkey.pem
```

Omit `--format` to use the default OpenPGP-style export where supported (`pgp`).

**Note:** This requires a connected token and a working `key_export_public` path in the device stack. If the command fails, check firmware and `galdra key list`.

### Publish public keys to keyservers (upload)

**`galdra` can fetch keys from keyservers (HKP) but does not upload keys.** Publishing is intentionally delegated to the OpenPGP ecosystem so policies (email verification, consent) stay with established tools.

Typical workflow after you have `my_pubkey.asc` from the previous section:

1. **Import the certificate into GnuPG** (one-time on the machine you use to publish):

```bash
gpg --import my_pubkey.asc
```

2. **Send to a keyserver** (example: default keyserver configured in `gpg`):

```bash
gpg --send-keys FINGERPRINT
```

Use the fingerprint shown by `gpg --list-keys` after import. For **keys.openpgp.org**, email verification and upload policies are described on [keys.openpgp.org](https://keys.openpgp.org/about); you can also use their **web upload** with an armoured public key file.

3. **Tell contacts to refresh** or give them your fingerprint so they can run `galdra contact fetch "<your-email>" --source keyserver`.

Servers listed under [Key fetching sources](#key-fetching-sources) are the same class of services; your organisation may require an internal HKP or LDAP instead of the public internet.

### Web Key Directory (WKD) upload

WKD means publishing the key under `https://openpgpkey.<domain>/...` (or the “advanced” layout). **`galdra` does not upload to your web server**; you (or IT) place the key material using your normal web or mail hosting process. After publication, anyone can run:

```bash
galdra contact fetch "you@yourdomain.example" --source wkd
```

### Revoke keys (OpenPGP)

**`galdra` has no `key revoke` command.** Revocation is an OpenPGP **certificate** operation. Use **GnuPG** (or another OpenPGP tool), then propagate the updated or revoked certificate the same way you publish keys.

1. Create or apply a **revocation certificate** for the key (for example `gpg --gen-revoke`, or revoke subkeys in your keyring as appropriate).
2. **Publish** the revocation so relying parties see it: `gpg --send-keys` to a keyserver, or your organisation’s directory, subject to policy.
3. On each **Galdra** host, **refresh** the contact so the local copy picks up the revoked key: `galdra contact refresh <identifier>`, or remove the contact with `galdra contact delete <identifier> --confirm` if you no longer want it listed.

For **token-resident** keys, revoking the published OpenPGP certificate does **not** erase private material on the token. To remove keys from hardware, use the next subsection (**Delete keys**).

### Delete keys (contacts, token slots, device)

“Delete” means different things depending on what you are removing.

**1. Delete a contact (remove someone else’s public key from this computer only)**  
This removes the row from the local SQLite database and drops group memberships for that identity. It does **not** delete anything from keyservers, LDAP, or anyone else’s machine.

```bash
galdra contact delete <identifier> --confirm
```

`<identifier>` is a contact **id**, **callsign**, **e-mail**, **Fluxer id**, **Discord id**, or **IRC id** as stored (same resolution as `galdra contact show`). To stop encrypting to someone without removing their contact row, remove them from groups with `galdra group remove <group> <identifier>` instead.

**2. Delete a private key from one token slot (destroy that slot on the device)**  
Irreversible: the private key material for that slot is erased on the token. Other slots are unchanged.

```bash
galdra key delete --slot <n> --confirm
```

You must pass `--confirm`; the tool may prompt again before proceeding. Requires a connected token.

**3. Wipe the entire token (all slots and device state)**  
Use when the device is lost, decommissioned, or you are intentionally returning to a blank state. This is stronger than deleting a single slot: **all** key material on the token is erased. You must pass `--confirm` and complete an additional confirmation step (for example typing the device serial when prompted).

```bash
galdra device zeroise --confirm
```

Recovery of secrets after zeroisation requires your **Shamir** (or other) backup process if the product provides one; see firmware documentation.

**4. Delete your published key from the internet**  
`galdra` does **not** remove keys from public keyservers or WKD. Use the keyserver or directory’s own process (many public servers **do not** support deletion; you rely on **revocation** instead — see [Revoke keys (OpenPGP)](#revoke-keys-openpgp) above).

### Summary

| Goal | Primary tool / command |
|------|-------------------------|
| Create key on token | `galdra key generate --type …` (when integrated); else GnuPG then future import |
| Export public key file | `galdra key export --slot N --format pgp > file.asc` |
| Upload to public keyserver | **Not `galdra`** — `gpg --import` then `gpg --send-keys`, or keys.openpgp.org web UI |
| Publish via WKD | Host the key on your domain; **`galdra` only fetches** with `contact fetch --source wkd` |
| Revoke | **GnuPG** (or equivalent); then `galdra contact refresh` or delete contact |
| Delete contact (local DB only) | `galdra contact delete <identifier> --confirm` |
| Delete one key on token | `galdra key delete --slot <n> --confirm` |
| Wipe whole token | `galdra device zeroise --confirm` |

---

## Purpose and scope

Galdra is a host-side token management and secure group communication tool
for the Galdralag firmware running on Baochip-1x hardware security tokens.

It serves any organisation or individual that needs to:

- Manage cryptographic identities and key material on a Galdralag token
- Fetch, store, and manage public keys for contacts from multiple sources
- Organise contacts into named groups that reflect operational structures
- Encrypt messages and files to named groups using multi-recipient encryption
- Operate reliably with or without network connectivity
- Maintain an auditable record of all key operations

The tool is not specific to any professional domain. Designed use cases
include but are not limited to:

- Hospital and clinical environments (patient data, on-call rosters)
- Law enforcement and security organisations (need-to-know group messaging)
- Search and rescue and emergency response (field operation, offline use)
- Amateur radio operators and emergency communications networks (ARES, RACES)
- Corporate and government environments requiring hardware-backed key management
- Any individual or small group requiring strong encrypted communication
  without dependency on a centralised service

---

## Target user populations

The tool must be usable by people who are not cryptographers. The following
user profiles inform design decisions throughout this specification.

### Clinical / hospital staff

- Doctors, nurses, ward administrators
- Work under time pressure; cannot tolerate complex workflows
- Group membership changes frequently with shift rosters
- Subject to GDPR, national medical data regulations, and hospital IT policy
- Existing infrastructure: Active Directory, smartcard PKI, badge authentication
- Connectivity: reliable inside hospital network; unreliable in field triage

### Security and law enforcement

- Officers, dispatchers, investigators, command staff
- Need-to-know access controls: recipients of a group message must not be
  able to infer the full recipient list
- Chain of custody requirements: every key operation must be logged with
  operator identity and timestamp
- May operate on isolated networks with no internet access
- Key lists for an operation may need to be assembled and distributed
  rapidly at the start of an incident

### Search and rescue / emergency response

- Incident commanders, field teams, logistics, communications officers
- May operate completely offline for days or weeks
- Personnel vary between activations; key lists must be updated quickly
  before deployment
- Devices carried in the field; risk of loss or capture is real
- Zeroisation policy must be clearly explained and easy to trigger

### Amateur radio operators

- Callsigns are globally registered unique identifiers
- Keys are often registered on public HKP keyservers under the callsign
- Emergency net operations (ARES, RACES) overlap with rescue use case
- Community is technically capable; CLI is acceptable

### General individuals and small groups

- Journalists, activists, legal professionals, anyone with a threat model
- No existing cryptographic infrastructure to integrate with
- Must be able to get started without an organisation behind them

---

## Architecture overview

The tool is divided into three tiers. Upper tiers depend on lower tiers;
lower tiers have no dependency on upper tiers.

```
┌─────────────────────────────────────────────────┐
│  Tier 2c: Desktop GUI (GTK4 + Rust, native)     │
├────────────────────┬────────────────────────────┤
│  Tier 2a: galdra   │  Tier 2b: galdrad           │
│  (CLI binary)      │  (local REST/socket daemon) │
├────────────────────┴────────────────────────────┤
│  Tier 1: galdra-core-host (Rust library)        │
│  Device · Keyserver · Database · Crypto · Audit │
└─────────────────────────────────────────────────┘
              │
              │ USB (host-tools protocol)
              ▼
    ┌──────────────────┐
    │ Galdralag token  │
    │ (Baochip-1x)     │
    └──────────────────┘
```

All cryptographic private key operations occur on the token. The host-side
tool never holds private key material. It holds public keys, group
definitions, and encrypted data only.

---

## Tier 1 — Core library: `galdra-core-host`

**Crate type:** `lib`
**Location:** `galdra-core-host/` (workspace root)
**`std`:** yes (host-side only, no `no_std` requirement)

This library provides all business logic. It has no user interface.
All CLI commands and daemon endpoints are thin wrappers over this library.

### Modules

| Module | Responsibility |
|--------|---------------|
| `device` | USB token communication using the host protocol defined in `docs/HOST_PROTOCOL.md` |
| `keyserver` | HKP keyserver queries, WKD lookups, LDAP queries, file import |
| `contacts` | Contact CRUD operations against the local database |
| `groups` | Group CRUD, membership queries, expiry enforcement |
| `encrypt` | Multi-recipient OpenPGP and age encryption/decryption |
| `sign` | OpenPGP signing and verification using token-resident keys |
| `db` | Database connection, schema migration, transaction management |
| `audit` | Append-only audit log writes |
| `sync` | Database export/import for offline key distribution |
| `config` | Configuration file loading and validation |

### Error handling

All public functions return `Result<T, GaldraError>`. `GaldraError` is a
typed enum covering all failure modes. No panics in library code.
Callers receive enough information to display a meaningful message to the
user.

---

## Tier 2a — CLI: `galdra`

**Crate type:** `bin`
**Location:** `galdra/` (workspace root)
**Framework:** `clap` with derive macros

The primary interface. Suitable for all technically capable users,
remote administration over SSH, scripting, and CI integration.

Full command reference is in [CLI command reference](#cli-command-reference).

The CLI must:

- Display progress for long-running operations (keyserver fetch, key generation)
- Prompt for PIN interactively when required; never accept PIN on the command
  line or from an environment variable (prevents shell history exposure)
- Confirm destructive operations (zeroise, delete) with an explicit
  `--confirm` flag or interactive prompt
- Support `--output json` for machine-readable output on any command
- Support `--quiet` for use in scripts (suppress progress, keep errors)
- Print all errors to stderr; all structured output to stdout

---

## Tier 2b — Local daemon: `galdrad`

**Crate type:** `bin`
**Location:** `galdrad/` (workspace root; same level as `galdra/` and `galdra-gtk/`)
**Protocol:** HTTP/1.1 over **TCP** on **127.0.0.1:8742** by default (`--listen`).
This keeps traffic on the loopback interface unless you explicitly bind to a
different address. A Unix domain socket or named pipe may be added later as
an optional transport; the shipping default is localhost HTTP.

The daemon exposes the `galdra-core-host` surface over HTTP so that **GTK4**
GUI clients and third-party integrations can call it without linking the
Rust library directly. Interactive OpenAPI documentation is served at
`/swagger-ui` on the same listener. There is **no** browser-based product
**web GUI** in scope (only machine-local API docs).

Authentication between clients and the daemon is **implicit** for the default
bind address (only local processes can connect). Binding beyond loopback
requires an explicit `--listen` choice and appropriate firewall and
organisational policy. An optional local bearer token may be added for
multi-user workstations.

The daemon does not persist any additional state beyond what the core
library already persists. It is stateless with respect to cryptographic
material — all private key operations still go to the token.

### API design

RESTful JSON API. Endpoints mirror the CLI command surface. Example:

```
GET    /contacts                  → list all contacts (JSON mirrors `Identity` fields)
POST   /contacts                  → create contact (**`email` required** in JSON; optional amateur-radio + postal + social ids)
GET    /contacts/{id}             → get a contact by id, callsign, email, Fluxer id, Discord id, or IRC id (resolver matches CLI)
PATCH  /contacts/{id}             → partial metadata update (same optional fields as POST body)
DELETE /contacts/{id}             → delete a contact

GET    /groups                    → list all groups
POST   /groups                    → create a group
GET    /groups/{name}             → get group with members
POST   /groups/{name}/members     → add member(s)
DELETE /groups/{name}/members/{id} → remove a member

POST   /encrypt                   → OpenPGP encrypt to group (uses contact DB; see `galdrad` handler)
POST   /decrypt                   → OpenPGP decrypt path (host public keys only — see handler errors)
POST   /sign                      → not implemented (HTTP 501 stub)
POST   /verify                    → not implemented (HTTP 501 stub)

GET    /device/status             → token presence and lock state
GET    /audit                     → audit rows
GET|POST /profiles, /profiles/:name  → cipher profile store

POST   /shamir/split              → token-backed profile Shamir split (shares as JSON)
POST   /shamir/recover            → token-backed recover from share armoured strings
GET    /shamir/share-info         → share metadata (query param)
```

Token **unlock** / **lock** remain **`galdra device`** CLI flows; they are **not** exposed as `galdrad` HTTP routes in the current crate.

---

## Tier 2c — Desktop GUI (GTK4)

**Location:** `galdra-gtk/` (workspace root; **`gtk4`** crate)
**Technology:** **GTK 4** with **Rust** bindings (**gtk4-rs** / **gtk-rs-core**). No HTML, no embedded browser engine, no SPA served over HTTP for the primary UI.

The desktop application is a **native** client over the `galdrad` HTTP API (same JSON routes as the CLI-oriented surface). It provides:

- Contact management with search and filter
- Group management with drag-and-drop membership editing
- Visual group membership editor for building complex groups
- File encryption and decryption via drag-and-drop
- Token status display (locked/unlocked, key slots used)
- Audit log viewer

The GTK4 GUI is appropriate for clinical staff, dispatch centres, and any
environment where a polished **desktop** interface matters more than scriptability.

It must work **without internet access**. UI resources ship with the application binary or load from the local filesystem; **no** runtime fetch of web frameworks.

---

## Build and installation

How to compile **host** tools (`galdra`, `galdrad`, `galdra-gtk`), install or remove them from your system, and how **firmware** builds relate to `xtask` and flashing, is documented in the repository root **[README.md](../README.md#build-install-and-uninstall)** under **Build, install, and uninstall**. That section also explains prerequisites (Rust, optional OpenSSL/GTK dev packages) and that firmware is programmed to the device rather than installed through Cargo.

---

## Identity model

An identity represents a person, role, or device that has a cryptographic
key. Identities are not limited to humans.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Stable primary key; never changes even if other fields do |
| `display_name` | text | Human-readable label; may be empty when only **e-mail** is used for display |
| `callsign` | text, unique | Amateur radio callsign; NULL if not applicable |
| `email` | text | Primary e-mail; **required** when adding a contact via CLI (`contact add`) or `POST /contacts`; otherwise taken from the OpenPGP User ID on fetch/import |
| `fluxer_id` | text | Optional Fluxer handle or id (**max 128** characters when set) |
| `discord_id` | text | Optional Discord user id (**max 32** characters when set) |
| `irc_id` | text | Optional IRC nick or `nick@server` style id (**max 128** characters when set) |
| `badge_number` | text | Hospital or security badge/employee ID |
| `organisation` | text | Employer, club, agency |
| `department` | text | Ward, division, team |
| `role` | text | Functional role: "on_call_physician", "net_control", "dispatch" |
| `note` | text | Free-text notes |
| `dmr_id` | integer | Optional DMR subscriber id (stored as SQLite `INTEGER`; when set must be **1..=16777215**) |
| `radio_affiliation` | text | Optional society / club / net label (**max 128** characters when set) |
| `street` | text | Optional postal street line (**max 512** characters when set) |
| `country` | text | Optional country name or code (**max 128** characters when set) |
| `postal_code` | text | Optional postal or ZIP (**max 32** characters when set) |
| `region` | text | Optional region, state, or county (**max 128** characters when set) |
| `pgp_fingerprint` | text | OpenPGP key fingerprint |
| `pgp_pubkey` | blob | Serialised OpenPGP public key packet |
| `fetched_at` | ISO8601 | When the key was last retrieved from its source |
| `expires_at` | ISO8601 | Key expiry; NULL if no expiry |
| `source` | text | Where the key came from: `keyserver`, `wkd`, `ldap`, `manual`, `file`, `peer` |

### Searching identities

**HKP / WKD fetch:** the upstream keyserver matches your query against **OpenPGP User ID** name, email, and comment fields (implementation-dependent).

**Local contact search (`galdra contact` search path and the `contact_search` helper in `galdra-core-host`):** textual `LIKE` search covers `display_name`, `callsign`, `email`, `badge_number`, `organisation`, `department`, `role`, `note`, `radio_affiliation`, **`dmr_id` as text**, `street`, `country`, `postal_code`, `region`, **`fluxer_id`**, **`discord_id`**, and **`irc_id`**. That lets a dispatcher find "Oslo", a postal prefix, organisation name, **and** amateur-radio affiliation or numeric DMR substring in one place on the workstation.

---

## Group model

A group is a named set of identity references. Groups are used as
recipients for multi-recipient encryption.

| Field | Type | Description |
|-------|------|-------------|
| `group_name` | text | Unique name: `net_control`, `on_call_icu`, `emergency_all` |
| `description` | text | Human-readable description of the group's purpose |
| `hidden_recipients` | boolean | If true, recipients cannot infer the full recipient list |
| `created_at` | ISO8601 | Creation timestamp |
| `created_by` | text | Operator who created the group |

### Group membership

Membership is a many-to-many relationship between groups and identities.

| Field | Type | Description |
|-------|------|-------------|
| `group_name` | text | References group |
| `identity_id` | UUID | References identity |
| `added_at` | ISO8601 | When added |
| `added_by` | text | Operator who added this member |
| `expires_at` | ISO8601 | Membership expiry; NULL = permanent. Used for shift-based membership |

### Dynamic group example

```
net_control:    W1ABC, K2XYZ, N3DEF
region_east:    KEY4, KEY5, KEY6
emergency_all:  W1ABC, K2XYZ, N3DEF, KEY4, KEY5, KEY6
```

`emergency_all` can be maintained either by explicit membership or by copying
members from existing groups one source at a time (`--from-group` accepts a single name per invocation):

```
galdra group add emergency_all --from-group net_control
galdra group add emergency_all --from-group region_east
```

### Shift-based membership expiry

For on-call rosters, a member is added with an explicit expiry:

```
galdra group add on_call_icu DR_SMITH --expires "2026-03-27T08:00:00Z"
```

At encrypt time, expired members are excluded and a warning is displayed.
Attempting to encrypt to a group with all members expired is an error.

---

## Database schema

The local database is SQLite stored at a user-configurable path
(default: `~/.local/share/galdra/galdra.db` on Linux,
`%APPDATA%\galdra\galdra.db` on Windows).

**Authoritative DDL** lives in **`galdra-core-host/migrations/`** (`001_initial.sql` through **`006_identity_address_fields.sql`**), applied in order by `galdra_core_host::db::Db`; `schema_migrations` records which versions ran. Older files gain new columns via `ALTER TABLE` (SQLite appends physically), but **`galdra` always selects identity columns by name** in the order the Rust API expects.

**`identities` — effective columns** (after migrations **005** amateur-radio fields and **006** postal hints):

```sql
-- Reference layout; exact CREATE/ALTER sequences are in the migration files above.
CREATE TABLE identities (
    id               TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    callsign         TEXT UNIQUE,
    email            TEXT,
    badge_number     TEXT,
    organisation     TEXT,
    department       TEXT,
    role             TEXT,
    note             TEXT,
    dmr_id           INTEGER,
    radio_affiliation TEXT,
    street           TEXT,
    country          TEXT,
    postal_code      TEXT,
    region           TEXT,
    pgp_fingerprint  TEXT,
    pgp_pubkey       BLOB,
    fetched_at       TEXT,
    expires_at       TEXT,
    source           TEXT NOT NULL DEFAULT 'manual'
);
CREATE INDEX idx_identities_callsign ON identities(callsign);
CREATE INDEX idx_identities_email    ON identities(email);
CREATE INDEX idx_identities_dmr_id   ON identities(dmr_id);
```

**Other core tables** (`groups`, `group_metadata`, `audit_log`, `config`, cipher profile / ephemeral-offer tables, and `audit_log` **prev_hash**) are defined in the same migration series; copy the shipped SQL rather than relying on this summary alone if you extend the schema.

Schema migrations are numbered sequentially under **`galdra-core-host/migrations/`** and applied
automatically at startup using **`schema_migrations`**.

---

## Key fetching sources

The tool fetches public keys from multiple sources depending on what is
available and configured. Sources are tried in the order specified in the
configuration file.

### HKP keyservers

Standard HTTP Keyserver Protocol. Default servers (tried in order):

1. `hkps://keys.openpgp.org` — email-verified, privacy-respecting
2. `hkps://keyserver.ubuntu.com` — broad coverage, no verification
3. `hkps://pgp.mit.edu` — legacy, broad coverage

Search query is matched against UID fields: name, email, comment.
A callsign in any of these fields will be found.

Configuration example:

```toml
[keyservers]
servers = [
    "hkps://keys.openpgp.org",
    "hkps://keyserver.ubuntu.com",
]
timeout_seconds = 10
```

### WKD (Web Key Directory)

Fetch a key by email address from the key owner's domain. No central
server required. Preferred for organisations that control their own domain.

```
galdra contact fetch "dr.smith@hospital.example.org" --source wkd
```

### LDAP / Active Directory

For hospital, corporate, and government environments with an internal
directory. Configuration:

```toml
[ldap]
url      = "ldaps://directory.hospital.example.org"
base_dn  = "dc=hospital,dc=example,dc=org"
bind_dn  = "cn=galdra-svc,ou=service-accounts,dc=hospital,dc=example,dc=org"
bind_pw_env = "GALDRA_LDAP_PASSWORD"  # read from environment, never stored
user_filter = "(|(mail={query})(cn={query})(employeeNumber={query}))"
key_attribute = "userCertificate"     # or "userSMIMECertificate"
```

### QR code import

Public key encoded as a QR code for exchange with no network connectivity.
The CLI accepts a QR code image file:

```
galdra contact import --qr <image.png>
```

The GUI supports camera scanning on platforms where a camera is available.

### USB file import

Direct import from a file containing an armoured OpenPGP public key,
a PEM certificate, or a DER-encoded public key:

```
galdra contact import --file <pubkey.asc>
```

### Peer token (direct device-to-device)

Fetch the public key directly from another Galdralag token connected to
the same host over USB. The peer token exposes its public key through the
unauthenticated USB mass-storage persona.

```
galdra contact fetch --peer   # fetches from the second connected token
```

### Manual entry

For keys received out-of-band (read over radio, phone, in person), import the armoured certificate from a file. The certificate **must** include an e-mail address in an OpenPGP User ID (that address is stored on the contact row):

```bash
galdra contact import --file received.asc
```

To record someone’s directory metadata **without** a key yet, use **`galdra contact add --email ...`** (e-mail required; other fields optional) as in [Contacts](#contacts).

---

## Multi-recipient encryption

**Implementation requirement:** the host tool (`galdra`) must implement the
multi-recipient pattern using [`sequoia-openpgp`](https://gitlab.com/sequoia-pgp/sequoia):
derive or import a message session key, wrap it to each recipient public key
(PKESK packets), symmetrically encrypt the payload, and emit ciphertext that
conforms to OpenPGP so recipients can decrypt with standard tools. Decryption,
signature verification, and key handling on the host must use the same crate for
a single, auditable OpenPGP stack.

### Primary format: OpenPGP

OpenPGP (RFC 4880 / RFC 9580) is the primary encryption format. It is
widely supported, integrates with existing GnuPG infrastructure, and
supports multi-recipient encryption natively.

Multi-recipient OpenPGP encrypts a single session key to each recipient's
public key. Any one recipient can decrypt the message using their private
key on the token. Recipients are identified by key fingerprint.

**Hidden recipients:** when `hidden_recipients = true` on a group, the
`--hidden-recipient` flag is used for each recipient, producing PKESK
packets with a zero key ID. Recipients cannot determine the full recipient
list from the ciphertext. This is required for law enforcement and
need-to-know contexts.

**Signing:** messages may optionally be signed with the sender's token-resident
key. The signature proves the sender's identity to any recipient who has
the sender's public key.

### Secondary format: age

age (Actually Good Encryption) is supported as an alternative format for
environments where OpenPGP compatibility is not required and simplicity
is preferred. The `age` crate provides multi-recipient encryption with
a cleaner API and smaller attack surface.

```
galdra encrypt --format age --group net_control --input message.txt
```

### Encryption workflow

```
1. Resolve group name to list of identity_ids
2. Filter out expired memberships; warn if any excluded
3. For each identity: retrieve pgp_pubkey from local database
4. Warn if any key is expired or missing
5. Abort if any required key is unavailable and --strict is set
6. Generate session key (from token TRNG if token connected, else OS CSPRNG)
7. Encrypt session key to each recipient public key
8. Encrypt message body with session key (AES-256-GCM)
9. Optionally sign with sender's token key
10. Write output file
11. Write audit log entry: operator, group, recipient count, timestamp
```

### Decryption workflow

```
1. Token must be connected and unlocked
2. Parse ciphertext to find PKESK packet matching token key fingerprint
3. Decapsulate session key on token (private key never leaves token)
4. Decrypt message body
5. If signed: verify signature against sender public key in local database
6. Write plaintext to output or stdout
7. Write audit log entry
```

---

## Offline operation

All functionality except key fetching works without network access.

### Pre-deployment preparation

Before going offline, an operator runs:

```
galdra sync export --output galdra-sync-20260326.db
```

This exports all contacts, groups, and public keys (no private keys) to a
portable file. Other operators import it:

```
galdra sync import --input galdra-sync-20260326.db
```

The sync package includes key expiry information. The import tool warns
if any keys in the package are expired or will expire during the planned
offline period.

### Key expiry warnings

At startup, if any key in the local database expires within 30 days (
configurable), the tool displays a warning listing the affected contacts
and groups. This prompts operators to refresh keys before going offline.

### Group export for field distribution

Groups can be exported to a compact signed package for distribution over
radio (as a data burst), USB drive, or satellite link:

```
galdra group export emergency_all --sign --output emergency_all.grp
galdra group import --input emergency_all.grp --verify
```

The package is signed with the exporting operator's token key so recipients
can verify it was not tampered with in transit.

---

## Audit logging

Every key operation is written to the `audit_log` table with full context.
The audit log is append-only. No UPDATE or DELETE operations are permitted
on `audit_log` by the application layer.

### Logged actions

| Action | Trigger |
|--------|---------|
| `device_unlock` | Token PIN accepted |
| `device_lock` | Token locked |
| `device_zeroise` | Zeroisation triggered |
| `key_import` | Public key added to database |
| `key_delete` | Contact deleted |
| `key_fetch` | Key fetched from keyserver, WKD, LDAP, or peer |
| `group_create` | Group created |
| `group_add_member` | Member added to group |
| `group_remove_member` | Member removed from group |
| `group_delete` | Group deleted |
| `encrypt` | Message encrypted to group or individual |
| `decrypt` | Message decrypted |
| `sign` | Message signed |
| `verify` | Signature verified |
| `sync_export` | Database exported |
| `sync_import` | Database imported |
| `config_change` | Configuration modified |

### Audit log export

```
galdra audit export --since 2026-03-01 --format csv --output audit.csv
galdra audit export --format json | galdra audit verify
```

The `verify` subcommand checks that the log has not been truncated or
modified by comparing a running hash chain. Each audit entry includes a
hash of the previous entry; the chain is verified from the first entry.

---

## PIN attempt policy

The PIN attempt threshold is configurable at provisioning time within the
range 3–10 inclusive. The **default is 3 attempts**, consistent with the
smartcard and hardware token industry standard (Nitrokey, YubiKey, ISO 7816).

The threshold is stored in the vault policy on the token, not in the host
software. The host software cannot modify the threshold after provisioning
without the current PIN.

**Rationale for default of 3:** the token implements full hardware-backed
zeroisation on threshold. A legitimate user who forgets their PIN recovers
through the Shamir secret sharing backup path, not by exhausting the counter.
Each additional attempt above 3 marginally increases brute-force exposure
with no compensating control.

**Rationale for allowing up to 10:** some operational environments (hospital
shift handover under time pressure, field conditions with gloves) make
fat-finger errors more likely. Organisations may configure a higher threshold
if their threat model accepts the marginal risk and their recovery procedure
is well established.

The threshold is set at provisioning time:

```
galdra device provision --pin-attempts 5
```

The minimum PIN length is 5 alphanumeric characters. This is enforced
at the parser boundary on both the token and the host tool. Attempts with
fewer than 5 characters are rejected without incrementing the counter.

---

## Integration requirements

### GnuPG compatibility

- Exported public keys are in standard OpenPGP armoured format readable
  by `gpg`.
- Encrypted output is in standard OpenPGP format decryptable by `gpg`
  if the recipient's private key is available (i.e. the token is the
  authority but the format is not proprietary).
- GnuPG keyserver protocol (HKP) is used for all keyserver operations.

### Active Directory / LDAP

- LDAP search and key retrieval as specified in [Key fetching sources](#key-fetching-sources).
- User accounts are not created or modified in LDAP. The tool is read-only
  with respect to directory services.

### SMTP / email

Not in scope for initial implementation. Future: send encrypted messages
directly via SMTP using OpenPGP.

### API clients

The `galdrad` REST API is documented in OpenAPI 3.0 format, generated from
the Rust code using `utoipa`. Third-party clients (hospital portal
software, dispatch systems) can integrate without depending on the Rust
binary.

---

## Operational guide: keys and Shamir

This section is a **how-to** for operators. It separates **public keys** (stored in the host database as contacts) from **private keys** (only on the token, never in `galdra`’s SQLite file). For **creating token keys, exporting, publishing, revoking, and deleting keys** with concrete commands, see [Token keys, publishing, revocation, and deletion](#token-keys-publishing-revocation-and-deletion) first.

### Public keys (contacts database)

The host stores **OpenPGP public certificates** for people you communicate with. It does **not** store their private keys.

| Goal | Command / action |
|------|------------------|
| **Fetch** a public key from a keyserver, WKD, or LDAP | `galdra contact fetch <query> --source keyserver` (or `wkd`, `ldap`) and optional `--server <hkps-url>` — configure keyservers and optional `[ldap]` in `config.toml`. |
| **Import** from a file | `galdra contact import --file <path.asc>` |
| **Import** from a QR image | `galdra contact import --qr <image.png>` |
| **Import** from another token on the same USB bus | `galdra contact fetch <query> --source peer` (requires a connected peer token; see implementation notes). |
| **Refresh** keys from their recorded source | `galdra contact refresh <identifier>` or `galdra contact refresh --all` |
| **Remove** a contact and its public key from the local database | `galdra contact delete <identifier> --confirm` — removes the row and group memberships; does not revoke the key on the internet. |
| **Optional metadata** (not cryptographically verified) | Set on add/edit: `--dmr-id`, `--radio-affiliation`, `--street`, `--country`, `--postal-code`, `--region`, `--fluxer-id`, `--discord-id`, `--irc-id` (CLI); same keys in **`galdrad`** JSON bodies; see **[Identity model](#identity-model)** and [README](../README.md#compile-and-install-host-tools-galdra-galdrad-galdra-gtk). |
| **List / show** | `galdra contact list`, `galdra contact show <id>` |

**Delete public key material locally** means **delete the contact** (`contact delete`). That only affects your machine.

### Revoking keys (OpenPGP)

`galdra` does **not** implement a dedicated “revoke certificate” command. OpenPGP **revocation** is done with **GnuPG** (or another OpenPGP tool):

1. Generate a revocation certificate or revoke the key in your keyring (`gpg --gen-revoke`, or revoke subkeys as appropriate).
2. Publish the updated certificate or revocation to a keyserver (`gpg --send-keys` / `keys.openpgp.org`), if your policy allows.
3. On Galdra hosts, **refresh** the contact (`galdra contact refresh`) so the local copy reflects the revoked key, or **delete** the contact if you no longer want it listed.

For **token-resident** keys, revocation of the OpenPGP certificate (if exported and published) follows the same ecosystem rules; the token may still hold the private material until you **delete the slot** or **zeroise** the device.

### Private keys (token slots)

All **private** key generation and use is intended to occur **on the Galdralag token**. The host never persists private key bytes in its database.

| Goal | Command / action |
|------|------------------|
| **List** keys in slots | `galdra key list` (USB token connected) |
| **Generate** a new key pair on the token | `galdra key generate --type <...>` — **specification target**; the CLI may return an error until device integration is complete. Use **provision** flow and product documentation for the current firmware. |
| **Import** a private key into a slot | `galdra key import --slot <n> --file <path>` — **specification target**; same caveat as generate. |
| **Export the public half** from a slot | `galdra key export --slot <n> --format pgp` (or `pem`, `der`) — public material only to stdout. |
| **Delete** a private key from a slot | `galdra key delete --slot <n> --confirm` — irreversible; destroys that slot’s key material on the token. |

**Generate / import private keys outside Galdra:** use **GnuPG** (`gpg --full-generate-key`) or your organisation’s process, then **import** into the token when `galdra key import` is available, or load via vendor tooling as documented for the hardware.

### Shamir secret sharing

**In firmware:** Shamir (k-of-n) splitting and recovery is implemented in the **`vault`** crate on the device (for example [`crates/vault/src/shamir.rs`](../crates/vault/src/shamir.rs) in this repository). It operates on **short secrets** (byte length bounds per profile), uses **GF(256)** arithmetic via `vsss-rs`, and participates in **recovery and backup policy** together with **HKDF** domain separation (`KeyPurpose::ShamirRecovery` in [`kdf_policy.rs`](../crates/vault/src/kdf_policy.rs)).

**Host tools (`galdra` / `galdrad`):** For **cipher profiles** that include a **Shamir** layer and a connected token, `galdra shamir split`, `shamir recover`, `shamir show-share`, and QR helpers orchestrate **`galdra-core-host::shamir_ops`**, which talks to the device. **`galdrad`** exposes **`POST /shamir/split`** and **`POST /shamir/recover`** for the same flows. Shares are sensitivity **physical artefacts** once exported; details: [API_REFERENCE.md](API_REFERENCE.md) and the Shamir subsection in [README](../README.md#shamir-secret-sharing-and-drive-encryption) plus the CLI block under [CLI command reference](#cli-command-reference).

**Operational takeaway:** treat Shamir shares like **physical recovery codes**: store offline, restrict who holds them, and assume compromise of k shares equals compromise of the recovered secret. For day-to-day OpenPGP, use **contacts** and **token slots** as described above.

---

## CLI command reference

### Device management

```
galdra device status
    Show token connection status, lock state, key slots used, firmware version.

galdra device unlock
    Prompt for PIN interactively. Unlock the token.
    PIN is never passed as a command-line argument.

galdra device lock
    Lock the token without disconnecting.

galdra device provision [--pin-attempts <3-10>] [--min-pin-length <5-32>]
    Initialise a blank token. Sets PIN policy. Generates device key.
    Requires confirmation prompt.

galdra device zeroise [--confirm]
    Trigger full hardware zeroisation. Irreversible.
    Requires explicit --confirm flag. No undo.

galdra device info
    Display firmware version, device serial, key slot inventory.
```

### Key management (token-resident keys)

```
galdra key list
    List key slots on the connected token.

galdra key generate --type <brainpool256|brainpool384|brainpool512|rsa2048|rsa4096|ed25519>
    Generate a new key pair on the token.

galdra key import --slot <n> --file <key.pem|key.der|key.p8>
    Import a private key into a token slot.
    Prompts for confirmation; key is sent directly to token and not stored on host.

galdra key export --slot <n> [--format pgp|pem|der]
    Export the public key from a token slot.

galdra key delete --slot <n> [--confirm]
    Delete a key from a token slot. Irreversible.
```

### Contact management

```
galdra contact add --email <addr> [--name <name>] [--callsign <call>] [--badge <id>] [--org <org>] [--role <role>]
    [--note <text>] [--dmr-id <id>] [--radio-affiliation <text>]
    [--street <line>] [--country <text>] [--postal-code <code>] [--region <text>]
    [--fluxer-id <id>] [--discord-id <id>] [--irc-id <id>]
    Add a contact manually without a key. --email is required.

galdra contact fetch <query> [--source keyserver|wkd|ldap|peer|file]
    [--server <url>]
    Fetch a public key for a contact. When searching the local database, text
    matches span display name, callsign, email, badge, organisation, department,
    role, notes, radio affiliation, DMR id, optional postal fields, and
    Fluxer / Discord / IRC ids.
    If contact does not exist locally, creates it (the certificate must carry an
    e-mail User ID).
    If contact exists, updates the key.

galdra contact import --file <pubkey.asc|cert.pem>
    Import a contact from a local file.

galdra contact import --qr <image.png>
    Import a contact from a QR-encoded public key.

galdra contact import --peer
    Fetch the public key from a second connected Galdralag token.

galdra contact show <identifier>
    Display full contact details including key fingerprint and expiry.
    <identifier> is a stored contact id, callsign, e-mail, Fluxer id, Discord id, or IRC id.

galdra contact list [--expired] [--org <org>] [--role <role>]
    List contacts, optionally filtered.

galdra contact edit <identifier> [--name <name>] [--email <addr>] [--callsign <call>]
    [--badge <id>] [--org <org>] [--role <role>] [--note <text>]
    [--dmr-id <id>] [--radio-affiliation <text>]
    [--street <line>] [--country <text>] [--postal-code <code>] [--region <text>]
    [--fluxer-id <id>] [--discord-id <id>] [--irc-id <id>]
    Update contact metadata. Does not change the key.

galdra contact delete <identifier> [--confirm]
    Delete a contact and remove from all groups.
    <identifier> as for show.

galdra contact refresh [--all] [<identifier>]
    Re-fetch key(s) from the original source.
    --all refreshes all contacts whose keys expire within 30 days.
```

### Group management

```
galdra group create <name> [--description <text>] [--hidden-recipients]
    Create a new group.

galdra group add <group> <identifier> [<identifier>...]
    [--expires <ISO8601>]
    Add one or more contacts to a group.
    Each <identifier> resolves like `galdra contact show` (id, callsign, e-mail, Fluxer, Discord, IRC).
    --expires sets automatic membership expiry (for on-call / shift use).

galdra group add <group> --from-group <other-group>
    Add all current members of another group to this group.

galdra group remove <group> <identifier> [<identifier>...]
    Remove one or more contacts from a group.

galdra group list
    List all groups with member counts.

galdra group show <group> [--include-expired]
    Show full group details and current members.
    Expired members are shown separately if --include-expired is given.

galdra group edit <group> [--description <text>] [--hidden-recipients <on|off>]
    Edit group metadata.

galdra group delete <group> [--confirm]
    Delete a group. Does not delete the member contacts.

galdra group export <group> [--sign] --output <file>
    Export group membership as a signed portable package.

galdra group import --input <file> [--verify]
    Import a group membership package. --verify checks the signature.
```

### Encryption and signing

```
galdra encrypt --group <name> --input <file> --output <file>
    [--sign] [--format pgp|age] [--strict]
    Encrypt a file to all current (non-expired) members of a group.
    --sign adds a signature from the token-resident key.
    --strict aborts if any member key is missing or expired.

galdra encrypt --to <identifier> [--to <identifier>...]
    --input <file> --output <file> [--sign] [--format pgp|age]
    Encrypt to one or more named contacts. Each <identifier> is resolved
    the same way as for `galdra contact show` (id, callsign, e-mail, Fluxer,
    Discord, or IRC id as stored).

galdra decrypt --input <file> --output <file>
    Decrypt a file. Token must be connected and unlocked.
    Displays sender identity if message is signed and sender is in contacts.

galdra sign --input <file> --output <file> [--detach]
    Sign a file with the token-resident key.
    --detach produces a separate signature file.

galdra verify --input <file> [--sig <file>] [--signer <identifier>]
    Verify a signature. If --signer is given, verifies against that
    specific contact's key (<identifier> as for `contact show`). Otherwise checks all known contacts.
```

### Synchronisation and audit

```
galdra sync export --output <file> [--sign]
    Export all contacts and groups (no private keys) for offline distribution.

galdra sync import --input <file> [--verify] [--merge|--replace]
    Import contacts and groups from a sync package.
    --merge adds new entries without removing existing ones.
    --replace replaces the local database (use with caution).

galdra audit show [--since <ISO8601>] [--action <action>] [--limit <n>]
    Display the audit log.

galdra audit export [--since <ISO8601>] [--format csv|json] --output <file>
    Export the audit log.

galdra audit verify
    Verify the audit log hash chain has not been modified or truncated.
```

### Shamir (cipher profile shares)

Requires a **connected unlocked token**. Profile must define Shamir thresholds; see [CIPHER_PROFILES.md](CIPHER_PROFILES.md).

```
galdra shamir split --slot <n> --profile <name> --output-dir <dir>
    Split material for the profile's Shamir layer; writes share files under output-dir.

galdra shamir recover --slot <n> --share <file> [--share <file>...] [--confirm]
    Recover from exported share files; imports combined result back to the token.

galdra shamir show-share --input <share-file>
    Print metadata from a share file (no secret dump).

galdra shamir export-qr --share <file> --output <png>
galdra shamir import-qr --input <png>
    Optional QR packaging for shares.
```

---

## Security requirements

### Private key material

- No private key material is ever held by the host-side tool.
- All private key operations (signing, decryption, key generation) occur
  on the token.
- The tool communicates with the token using the signed, authenticated
  protocol defined in `docs/HOST_PROTOCOL.md`.

### PIN handling

- The PIN is read interactively via a terminal prompt using a library that
  suppresses echo (e.g. `rpassword`).
- The PIN is never stored in a file, environment variable, shell history,
  process argument, or log entry.
- The PIN buffer is zeroised immediately after use.

### Public key trust

- Keys fetched from `keys.openpgp.org` are email-verified by that server.
- Keys fetched from other sources are not automatically trusted.
- The tool displays key fingerprint and source for user confirmation on
  first import.
- A configurable trust policy allows organisations to set rules (e.g.
  "only accept keys from our LDAP server").

### Database security

- The local SQLite database contains public keys only. It is not encrypted
  by default. On platforms where the OS provides user-level encryption
  (FileVault, BitLocker, LUKS), users are encouraged to rely on that.
- Optional **SQLCipher** encryption at rest: set `database_key_env` in `config.toml` to the name of an
  environment variable that holds the passphrase; `galdra` / `galdrad` pass it into `Db::open` via
  `database_key_from_env` (see `galdra-core-host`). The same passphrase is required on every open.

### Audit log integrity

- The audit log uses a hash chain: each entry includes a hash of the
  previous entry. Tampering is detectable by `galdra audit verify`.
- The audit log is not encrypted. It contains operation metadata only —
  no key material, no message content.

### Network security

- All keyserver connections use TLS (HTTPS/HKP over TLS).
- Certificate validation is performed using the system trust store.
- LDAP connections use LDAPS (TLS). Plain LDAP is rejected unless
  explicitly overridden in configuration with a warning.

---

## Compliance considerations

The following compliance frameworks are relevant to specific user populations.
The tool is designed to support compliance but compliance itself is the
responsibility of the deploying organisation.

| Framework | Relevant user population | Relevant features |
|-----------|--------------------------|-------------------|
| GDPR (EU) | Hospital, any EU deployment | Audit log, key expiry, contact deletion |
| HIPAA (US) | US hospital | Audit log, access control via token |
| BSI TR-03116 | German government | Brainpool curve support, BSI-approved algorithms |
| ISO 27001 | Corporate security | Audit log, policy enforcement |
| FIPS 140-3 | US federal, law enforcement | Token-resident key operations; host software is not FIPS-certified |

---

## Implementation status (original phased roadmap)

The **phase labels** below are the **original build order**. Most items are **already implemented** in
this repository; remaining gaps are noted where readers commonly hit them (for example token-side
key generation still depends on firmware integration; some `galdrad` routes remain stubs).

**Phase 1 — Core library and CLI (basic)** — **done**
- `galdra-core-host`: device communication, SQLite schema, contact and group CRUD
- `galdra`: `device`, `key`, `contact`, `group`
- HKP keyserver fetch (`galdra contact fetch --source keyserver`; `[keyservers]` in `config.toml`)
- WKD fetch (`--source wkd`)

**Phase 2 — Encryption and signing** — **done** (host-side; token behaviour varies by firmware build)
- Multi-recipient OpenPGP encrypt/decrypt via `sequoia-openpgp` (see [Multi-recipient encryption](#multi-recipient-encryption))
- `galdra encrypt`, `decrypt`, `sign`, `verify`; hidden recipients where documented
- `galdra encrypt --format age` (age)

**Phase 3 — Audit and sync** — **done**
- Audit log with hash chain (`galdra audit …`)
- `galdra sync export` / `sync import`
- Group export/import (`galdra group export` / `group import`)

**Phase 4 — Daemon and GTK4 desktop GUI** — **done** (`galdrad`, OpenAPI; `galdra-gtk`; not every
HTTP route mirrors full CLI depth yet)

**Phase 5 — Advanced integration** — **mostly done**
- LDAP / Active Directory: `galdra contact fetch --source ldap` with `[ldap]` in `config.toml`
- QR code import: `galdra contact import --qr`
- age: see Phase 2 (`--format age`)
- Optional SQLCipher: `database_key_env` in `config.toml` (see [Database security](#database-security))

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing |
| `rusqlite` | SQLite database (bundled SQLCipher available for optional encryption) |
| `sequoia-openpgp` | OpenPGP key parsing; multi-recipient encryption/decryption and signing in `galdra` (mandated) |
| `sequoia-net` | HKP keyserver and WKD fetching (`galdra-core-host::keyserver`) |
| `age` | age format encryption (`galdra encrypt --format age`) |
| `ldap3` | LDAP / Active Directory (`galdra contact fetch --source ldap`) |
| `rusb` | USB device communication |
| `rpassword` | Secure PIN prompt (no echo) |
| `zeroize` | PIN buffer zeroisation |
| `serde` / `serde_json` | JSON serialisation |
| `toml` | Configuration file parsing |
| `uuid` | Identity UUID generation |
| `chrono` | Timestamps and expiry calculations |
| `sha2` | Audit log hash chain |
| `axum` | HTTP daemon (`galdrad`) |
| `utoipa` | OpenAPI spec generation (`galdrad`) |
| `tokio` | Async runtime for daemon and network I/O |
| `tracing` | Structured logging |
| `image` / `rqrr` | QR code decode for `galdra contact import --qr` |

All dependencies must be evaluated for open security advisories before
inclusion. Pin versions in `Cargo.lock`. Review with `cargo audit` on
every build.

---

## Ephemeral key offer management (`galdra epk`)

The `epk` subcommand manages the lifecycle of out-of-band ephemeral BrainpoolP256r1 key offers
distributed as GnuPG sign-and-encrypt blobs (`.epk.gpg`). See `docs/EPHEMERAL_KEY_EXCHANGE.md`
for the full specification and interoperability notes.

### `galdra epk generate`

Generate a BrainpoolP256r1 ephemeral keypair and write a signed, encrypted `.epk.gpg` offer file.

```
galdra epk generate \
    --gpg-key-id <KEY_ID_OR_FINGERPRINT> \
    --recipient <RECIPIENT> [--recipient <RECIPIENT>...] \
    [--expires <SECONDS>] \
    --output <FILE.epk.gpg> \
    [--operator <LABEL>]
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--gpg-key-id` | Yes | — | GnuPG key ID or fingerprint used to sign the offer and identify the issuer. |
| `--recipient` | Yes (repeat) | — | GnuPG key IDs or fingerprints that can decrypt the offer. |
| `--expires` | No | `86400` | Offer lifetime in seconds from now. |
| `--output` | Yes | — | Output path for the `.epk.gpg` file. |
| `--operator` | No | — | Operator label written to the audit log. |

The ephemeral private scalar is stored in the database for later use in ECDH derivation. Requires
`gpg` on `PATH`.

### `galdra epk import`

Decrypt and validate a peer's `.epk.gpg` offer and store it in the local database.

```
galdra epk import <FILE.epk.gpg> \
    --verify-fingerprint <FINGERPRINT> \
    [--operator <LABEL>]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `FILE.epk.gpg` | Yes | Path to the received `.epk.gpg` file. |
| `--verify-fingerprint` | Yes | Expected GnuPG fingerprint of the offer issuer (hex, spaces optional). |
| `--operator` | No | Operator label written to the audit log. |

Rejects offers with a past `expires_at`, `consumed: true`, mismatched fingerprint, or invalid
inner detached signature. Requires `gpg` on `PATH` with the recipient secret key available.

### `galdra epk status`

List all stored ephemeral key offers.

```
galdra epk status [--emit json]
```

Columns shown: session ID, long-term fingerprint (last 16 hex chars), expiry Unix timestamp,
consumed flag, revoked flag, and whether the local private key is stored (self-generated offers).

### `galdra epk expire`

Immediately revoke an offer and zero its private key from the database. This is the manual
revocation path; it does not wait for the automatic `expires_at` expiry.

```
galdra epk expire <SESSION_ID> --confirm
```

| Argument | Required | Description |
|----------|----------|-------------|
| `SESSION_ID` | Yes | The `session_id` of the offer to revoke (from `galdra epk status`). |
| `--confirm` | Yes | Explicit confirmation flag; prevents accidental invocations. |

Sets `revoked=1` and clears `my_private_key_pem` in the database. Appends an `epk_reject` audit
event with `reason: manual_revoke`.

---

## Out of scope

The following are explicitly out of scope for this specification. They may
be addressed in future specifications.

- **Private key backup to cloud services.** Shamir secret sharing on the
  token provides the recovery path. No cloud key escrow.
- **Key generation on the host.** All key generation occurs on the token.
- **Message transport.** The tool encrypts and decrypts files. It does not
  send or receive messages over any network. Integration with email, radio,
  or messaging systems is the responsibility of the surrounding workflow.
- **Certificate authority operations.** The tool is not a CA and does not
  issue certificates.
- **Multi-device synchronisation of private keys.** Private keys are
  token-resident and are not synchronised between tokens. Public key
  databases are synchronised via the sync package mechanism.
- **Mobile native applications.** The GTK4 desktop GUI does not target
  mobile; native iOS/Android apps are not in scope. A separate design would
  be required for mobile toolkits.
- **FIPS 140-3 certification of the host software.** The token hardware
  is the security boundary. The host software is not submitted for
  certification.
