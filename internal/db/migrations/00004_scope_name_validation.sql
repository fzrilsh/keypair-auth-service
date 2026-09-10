-- +goose Up
ALTER TABLE scopes DROP CONSTRAINT IF EXISTS scopes_name_check;
ALTER TABLE scopes
    ADD CONSTRAINT scopes_name_check
    CHECK (name = btrim(name) AND name <> '' AND name !~ E'[[:space:][:cntrl:]]');

-- +goose Down
ALTER TABLE scopes DROP CONSTRAINT IF EXISTS scopes_name_check;
ALTER TABLE scopes
    ADD CONSTRAINT scopes_name_check
    CHECK (name = btrim(name) AND name <> '' AND name !~ E'[[:space:]]');
