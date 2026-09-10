-- +goose Up
CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (name = btrim(name) AND name <> '' AND name !~ E'[[:space:]]')
);
CREATE INDEX scopes_active_name_idx ON scopes (name) WHERE disabled_at IS NULL;

CREATE TABLE invite_scopes (
    invite_id UUID NOT NULL REFERENCES invite_tokens(invite_id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES scopes(id),
    PRIMARY KEY (invite_id, scope_id)
);

CREATE TABLE device_scopes (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES scopes(id),
    PRIMARY KEY (device_id, scope_id)
);

-- +goose Down
DROP TABLE IF EXISTS device_scopes;
DROP TABLE IF EXISTS invite_scopes;
DROP TABLE IF EXISTS scopes;
