CREATE TABLE identities (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    callsign        TEXT UNIQUE,
    email           TEXT,
    badge_number    TEXT,
    organisation    TEXT,
    department      TEXT,
    role            TEXT,
    note            TEXT,
    pgp_fingerprint TEXT,
    pgp_pubkey      BLOB,
    fetched_at      TEXT,
    expires_at      TEXT,
    source          TEXT NOT NULL DEFAULT 'manual'
);

CREATE TABLE groups (
    group_name  TEXT NOT NULL,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    added_at    TEXT NOT NULL,
    added_by    TEXT,
    expires_at  TEXT,
    PRIMARY KEY (group_name, identity_id)
);

CREATE TABLE group_metadata (
    group_name         TEXT PRIMARY KEY,
    description        TEXT,
    hidden_recipients  INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    created_by         TEXT
);

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    operator      TEXT,
    action        TEXT NOT NULL,
    subject       TEXT,
    detail        TEXT,
    device_serial TEXT
);

CREATE TABLE config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX idx_identities_callsign ON identities(callsign);
CREATE INDEX idx_identities_email    ON identities(email);
CREATE INDEX idx_groups_identity     ON groups(identity_id);
CREATE INDEX idx_audit_timestamp     ON audit_log(timestamp);
