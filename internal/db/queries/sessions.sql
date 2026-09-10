-- name: InsertSession :exec
INSERT INTO admin_sessions (session_id_hash, admin_id, csrf_token_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetSession :one
SELECT session_id_hash, admin_id, csrf_token_hash, created_at, expires_at
FROM admin_sessions WHERE session_id_hash = $1 AND expires_at > now();

-- name: DeleteSession :exec
DELETE FROM admin_sessions WHERE session_id_hash = $1;

-- name: CleanupSessions :execrows
DELETE FROM admin_sessions WHERE expires_at < $1;
