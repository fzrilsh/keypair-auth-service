-- name: GetNonceForUpdate :one
SELECT device_id, nonce, expires_at FROM auth_nonces WHERE device_id = $1 FOR UPDATE;

-- name: UpsertNonce :exec
INSERT INTO auth_nonces (device_id, nonce, expires_at) VALUES ($1, $2, $3)
ON CONFLICT (device_id) DO UPDATE SET nonce = EXCLUDED.nonce, expires_at = EXCLUDED.expires_at;

-- name: DeleteNonce :exec
DELETE FROM auth_nonces WHERE device_id = $1;

-- name: CleanupNonces :execrows
DELETE FROM auth_nonces WHERE expires_at < $1;
