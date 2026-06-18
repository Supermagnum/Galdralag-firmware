CREATE TABLE ephemeral_offers (
    session_id            TEXT PRIMARY KEY,
    epk_hex               TEXT NOT NULL,
    curve                 TEXT NOT NULL DEFAULT 'brainpoolP256r1',
    long_term_fingerprint TEXT NOT NULL,
    signature_hex         TEXT NOT NULL,
    expires_at            INTEGER NOT NULL,
    created_at            INTEGER NOT NULL,
    consumed              INTEGER NOT NULL DEFAULT 0,
    revoked               INTEGER NOT NULL DEFAULT 0,
    imported_at           TEXT NOT NULL,
    my_private_key_pem    BLOB
);

CREATE INDEX idx_ephemeral_offers_expires ON ephemeral_offers(expires_at);
