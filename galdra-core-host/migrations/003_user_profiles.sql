CREATE TABLE user_profiles (
    name        TEXT PRIMARY KEY NOT NULL,
    description TEXT,
    serialised  BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    created_by  TEXT
);
