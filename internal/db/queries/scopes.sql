-- name: ListScopes :many
SELECT id, name, disabled_at, created_at
FROM scopes ORDER BY name;

-- name: ListActiveScopes :many
SELECT id, name, disabled_at, created_at
FROM scopes WHERE disabled_at IS NULL ORDER BY name;

-- name: GetScope :one
SELECT id, name, disabled_at, created_at
FROM scopes WHERE id = $1;

-- name: GetActiveScope :one
SELECT id, name, disabled_at, created_at
FROM scopes WHERE id = $1 AND disabled_at IS NULL;

-- name: InsertScope :one
INSERT INTO scopes (name) VALUES ($1)
RETURNING id, name, disabled_at, created_at;

-- name: DisableScope :one
UPDATE scopes SET disabled_at = COALESCE(disabled_at, now())
WHERE id = $1
RETURNING id, name, disabled_at, created_at;

-- name: EnableScope :one
UPDATE scopes SET disabled_at = NULL
WHERE id = $1
RETURNING id, name, disabled_at, created_at;

-- name: ListInviteScopes :many
SELECT s.id, s.name, s.disabled_at, s.created_at
FROM invite_scopes i
JOIN scopes s ON s.id = i.scope_id
WHERE i.invite_id = $1
ORDER BY s.name;

-- name: ListDeviceScopes :many
SELECT s.id, s.name, s.disabled_at, s.created_at
FROM device_scopes d
JOIN scopes s ON s.id = d.scope_id
WHERE d.device_id = $1
ORDER BY s.name;

-- name: ListEnabledDeviceScopes :many
SELECT s.name
FROM device_scopes d
JOIN scopes s ON s.id = d.scope_id
WHERE d.device_id = $1 AND s.disabled_at IS NULL
ORDER BY s.name;

-- name: InsertInviteScope :exec
INSERT INTO invite_scopes (invite_id, scope_id) VALUES ($1, $2);

-- name: CopyInviteScopesToDevice :exec
INSERT INTO device_scopes (device_id, scope_id)
SELECT $1, scope_id FROM invite_scopes WHERE invite_id = $2;

-- name: DeleteDeviceScopes :exec
DELETE FROM device_scopes WHERE device_id = $1;

-- name: InsertDeviceScope :exec
INSERT INTO device_scopes (device_id, scope_id) VALUES ($1, $2);
