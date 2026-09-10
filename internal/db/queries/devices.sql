-- name: GetDevice :one
SELECT id, user_id, public_key, device_name, status, created_at, approved_at
FROM devices WHERE id = $1;

-- name: GetApprovedDevice :one
SELECT id, user_id, public_key, device_name, status, created_at, approved_at
FROM devices WHERE id = $1 AND status = 'approved';

-- name: GetApprovedDeviceForUpdate :one
SELECT id, user_id, public_key, device_name, status, created_at, approved_at
FROM devices WHERE id = $1 AND status = 'approved'
FOR UPDATE;

-- name: ListDevices :many
SELECT id, user_id, public_key, device_name, status, created_at, approved_at
FROM devices ORDER BY created_at DESC;

-- name: InsertDevice :one
INSERT INTO devices (user_id, public_key, device_name)
VALUES ($1, $2, $3)
RETURNING id, user_id, public_key, device_name, status, created_at, approved_at;

-- name: ApproveDevice :one
UPDATE devices SET status = 'approved', approved_at = COALESCE(approved_at, now())
WHERE id = $1 AND status = 'pending'
RETURNING id, user_id, public_key, device_name, status, created_at, approved_at;

-- name: RevokeDevice :one
UPDATE devices SET status = 'revoked'
WHERE id = $1 AND status = 'approved'
RETURNING id, user_id, public_key, device_name, status, created_at, approved_at;
