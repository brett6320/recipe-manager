CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    handle        BLOB NOT NULL UNIQUE,          -- 64 random bytes, WebAuthn user handle
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE webauthn_credentials (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    data          BLOB NOT NULL,                 -- JSON-encoded webauthn.Credential
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_used_at  TEXT
);
CREATE INDEX idx_webauthn_user ON webauthn_credentials(user_id);

CREATE TABLE totp (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc    BLOB NOT NULL,                 -- AES-GCM encrypted base32 secret
    confirmed     INTEGER NOT NULL DEFAULT 0,
    last_counter  INTEGER NOT NULL DEFAULT 0,    -- highest accepted time step, replay guard
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE sessions (
    token_hash    BLOB PRIMARY KEY,              -- SHA-256 of the cookie token
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at    TEXT NOT NULL,
    ip            TEXT NOT NULL,
    user_agent    TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE invites (
    code_hash     BLOB PRIMARY KEY,
    created_by    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at    TEXT NOT NULL,
    used_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    used_at       TEXT
);

CREATE TABLE folders (
    id            INTEGER PRIMARY KEY,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id     INTEGER REFERENCES folders(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (owner_id, parent_id, name)
);
CREATE INDEX idx_folders_parent ON folders(parent_id);

CREATE TABLE groups (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE group_members (
    group_id      INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_group_members_user ON group_members(user_id);

-- A share grants view or edit on one recipe or one folder (recursively) to
-- one user or one group.
CREATE TABLE shares (
    id            INTEGER PRIMARY KEY,
    subject_type  TEXT NOT NULL CHECK (subject_type IN ('recipe','folder')),
    subject_id    INTEGER NOT NULL,
    grantee_type  TEXT NOT NULL CHECK (grantee_type IN ('user','group')),
    grantee_id    INTEGER NOT NULL,
    perm          TEXT NOT NULL CHECK (perm IN ('view','edit')),
    created_by    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (subject_type, subject_id, grantee_type, grantee_id)
);
CREATE INDEX idx_shares_grantee ON shares(grantee_type, grantee_id);
CREATE INDEX idx_shares_subject ON shares(subject_type, subject_id);

CREATE TABLE recipes (
    id            INTEGER PRIMARY KEY,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id     INTEGER REFERENCES folders(id) ON DELETE SET NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    servings      TEXT NOT NULL DEFAULT '',
    prep_minutes  INTEGER,
    cook_minutes  INTEGER,
    source_url    TEXT NOT NULL DEFAULT '',
    image_url     TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX idx_recipes_owner_folder ON recipes(owner_id, folder_id);

CREATE TABLE recipe_ingredients (
    recipe_id     INTEGER NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
    pos           INTEGER NOT NULL,
    text          TEXT NOT NULL,
    PRIMARY KEY (recipe_id, pos)
);

CREATE TABLE recipe_steps (
    recipe_id     INTEGER NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
    pos           INTEGER NOT NULL,
    text          TEXT NOT NULL,
    PRIMARY KEY (recipe_id, pos)
);

CREATE TABLE recipe_tags (
    recipe_id     INTEGER NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
    tag           TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (recipe_id, tag)
);
CREATE INDEX idx_recipe_tags_tag ON recipe_tags(tag);
