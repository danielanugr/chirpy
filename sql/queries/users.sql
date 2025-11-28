-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
  gen_random_uuid(), NOW(), NOW(), $1, $2
) RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByRefreshToken :one
SELECT rt.*, u.* FROM refresh_tokens rt
JOIN users u ON rt.user_id = u.id
WHERE rt.token = $1 AND rt.revoked_at IS NULL AND rt.expires_at > NOW();

-- name: EditUser :one
UPDATE users
SET email = $1, hashed_password = $2, updated_at = NOW()
WHERE id = $3
RETURNING *;

-- name: UpgradeUser :one
UPDATE users
SET is_chirpy_red = true, updated_at = NOW()
WHERE ID = $1
RETURNING *;