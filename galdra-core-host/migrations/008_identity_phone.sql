-- Optional phone number (submitter-declared; see server.md).
ALTER TABLE identities ADD COLUMN phone_number TEXT;

CREATE INDEX IF NOT EXISTS idx_identities_phone_number ON identities(phone_number);
