-- name: GetAdminByEmail :one
SELECT id, email, password_hash, created_at FROM admins WHERE email = $1;

-- name: InsertAdmin :one
INSERT INTO admins (email, password_hash) VALUES ($1, $2)
RETURNING id, email, password_hash, created_at;
