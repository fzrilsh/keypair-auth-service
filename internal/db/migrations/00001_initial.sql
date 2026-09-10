-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    public_key BYTEA NOT NULL,
    device_name TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    UNIQUE (public_key)
);
CREATE INDEX devices_user_id_idx ON devices (user_id);
CREATE INDEX devices_status_created_idx ON devices (status, created_at DESC);

CREATE TABLE invite_tokens (
    token_hash BYTEA PRIMARY KEY,
    token_prefix TEXT NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX invite_tokens_expiry_idx ON invite_tokens (expires_at);

CREATE TABLE auth_nonces (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    nonce BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX auth_nonces_expiry_idx ON auth_nonces (expires_at);

CREATE TABLE admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_sessions (
    session_id_hash BYTEA PRIMARY KEY,
    admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX admin_sessions_expiry_idx ON admin_sessions (expires_at);

-- +goose Down
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS admins;
DROP TABLE IF EXISTS auth_nonces;
DROP TABLE IF EXISTS invite_tokens;
DROP TABLE IF EXISTS devices;
