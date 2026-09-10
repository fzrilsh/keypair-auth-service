-- +goose Up
ALTER TABLE invite_tokens ADD COLUMN invite_id UUID DEFAULT gen_random_uuid();
UPDATE invite_tokens SET invite_id = gen_random_uuid() WHERE invite_id IS NULL;
ALTER TABLE invite_tokens ALTER COLUMN invite_id SET NOT NULL;
ALTER TABLE invite_tokens ADD CONSTRAINT invite_tokens_invite_id_key UNIQUE (invite_id);

-- +goose Down
ALTER TABLE invite_tokens DROP CONSTRAINT IF EXISTS invite_tokens_invite_id_key;
ALTER TABLE invite_tokens DROP COLUMN IF EXISTS invite_id;
