-- Optional amateur-radio metadata per contact / identity (see docs / server WoT sketches).
ALTER TABLE identities ADD COLUMN dmr_id INTEGER;
ALTER TABLE identities ADD COLUMN radio_affiliation TEXT;

CREATE INDEX IF NOT EXISTS idx_identities_dmr_id ON identities(dmr_id);
