-- name: GetSetupKey :one
SELECT * FROM setup_keys
WHERE account_id = $1 AND id = $2;

-- name: GetSetupKeyForUpdate :one
SELECT * FROM setup_keys
WHERE account_id = $1 AND id = $2
FOR UPDATE;

-- name: GetSetupKeyBySecret :one
SELECT * FROM setup_keys
WHERE key_secret = $1;

-- name: ListAccountSetupKeys :many
SELECT * FROM setup_keys
WHERE account_id = $1
ORDER BY created_at, id;

-- name: CreateSetupKey :exec
INSERT INTO setup_keys (
  id, account_id, key, key_secret, name, type, created_at, expires_at, updated_at,
  revoked, used_times, last_used, auto_groups, usage_limit, ephemeral, allow_extra_dns_labels
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9,
  $10, $11, $12, $13, $14, $15, $16
);

-- name: IncrementSetupKeyUsage :execrows
UPDATE setup_keys
SET used_times = used_times + 1, last_used = $3, updated_at = $3
WHERE account_id = $1 AND id = $2;

-- name: DeleteSetupKey :execrows
DELETE FROM setup_keys
WHERE account_id = $1 AND id = $2;
