-- name: InsertInvite :exec
INSERT INTO invite_tokens (invite_id, token_hash, token_prefix, user_id, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: RedeemInvite :one
UPDATE invite_tokens SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING user_id;

-- name: ListInvites :many
SELECT invite_id, token_prefix, user_id, expires_at, used_at, created_at
FROM invite_tokens ORDER BY created_at DESC;

-- name: RemoveInvite :execrows
DELETE FROM invite_tokens WHERE invite_id = $1 AND used_at IS NULL;

-- name: CleanupInvites :execrows
DELETE FROM invite_tokens WHERE expires_at < $1 OR (used_at IS NOT NULL AND used_at < $2);
