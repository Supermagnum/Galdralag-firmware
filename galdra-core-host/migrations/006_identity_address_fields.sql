-- Optional postal / location hints for contacts (not verified; local directory only).
ALTER TABLE identities ADD COLUMN street TEXT;
ALTER TABLE identities ADD COLUMN country TEXT;
ALTER TABLE identities ADD COLUMN postal_code TEXT;
ALTER TABLE identities ADD COLUMN region TEXT;
