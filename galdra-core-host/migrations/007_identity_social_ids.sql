-- Optional Fluxer, Discord, and IRC identifiers (submitter-declared; see server.md).
ALTER TABLE identities ADD COLUMN fluxer_id TEXT;
ALTER TABLE identities ADD COLUMN discord_id TEXT;
ALTER TABLE identities ADD COLUMN irc_id TEXT;

CREATE INDEX IF NOT EXISTS idx_identities_fluxer_id ON identities(fluxer_id);
CREATE INDEX IF NOT EXISTS idx_identities_discord_id ON identities(discord_id);
CREATE INDEX IF NOT EXISTS idx_identities_irc_id ON identities(irc_id);
