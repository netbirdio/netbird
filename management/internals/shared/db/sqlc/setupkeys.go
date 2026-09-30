package sqlc

import (
	"context"
	"database/sql"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/sqlc/gen"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// SetupKeyRepository is the setup key store on top of the generated queries.
// It follows the repository shape of the module refactor: the connection is
// shared, WithTx binds a copy to a transaction and the lock strength is passed
// per read.
type SetupKeyRepository struct {
	conn *db.Conn
	tx   *db.Tx
}

// NewSetupKeyRepository returns a repository that runs without a transaction.
func NewSetupKeyRepository(conn *db.Conn) *SetupKeyRepository {
	return &SetupKeyRepository{conn: conn}
}

// WithTx returns a copy bound to tx.
func (r *SetupKeyRepository) WithTx(tx *db.Tx) *SetupKeyRepository {
	return &SetupKeyRepository{conn: r.conn, tx: tx}
}

func (r *SetupKeyRepository) queries() gen.Querier {
	return New(r.conn.DB(r.tx), r.conn.Engine())
}

// Get returns one setup key of the account, holding the requested row lock
// until the transaction ends.
func (r *SetupKeyRepository) Get(ctx context.Context, lockStrength db.LockingStrength, accountID, id string) (*types.SetupKey, error) {
	var row gen.SetupKey
	var err error
	if lockStrength == db.LockingStrengthNone {
		row, err = r.queries().GetSetupKey(ctx, gen.GetSetupKeyParams{AccountID: accountID, ID: id})
	} else {
		row, err = r.queries().GetSetupKeyForUpdate(ctx, gen.GetSetupKeyForUpdateParams{AccountID: accountID, ID: id})
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.NewSetupKeyNotFoundError(id)
	}
	if err != nil {
		log.WithContext(ctx).Errorf("get setup key %s: %v", id, err)
		return nil, status.Errorf(status.Internal, "get setup key")
	}
	return toSetupKey(row), nil
}

// GetBySecret returns the setup key with the given hashed secret, whatever account it belongs to.
func (r *SetupKeyRepository) GetBySecret(ctx context.Context, keySecret string) (*types.SetupKey, error) {
	row, err := r.queries().GetSetupKeyBySecret(ctx, keySecret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Errorf(status.NotFound, "setup key not found")
	}
	if err != nil {
		log.WithContext(ctx).Errorf("get setup key by secret: %v", err)
		return nil, status.Errorf(status.Internal, "get setup key")
	}
	return toSetupKey(row), nil
}

// List returns the setup keys of the account in creation order.
func (r *SetupKeyRepository) List(ctx context.Context, accountID string) ([]*types.SetupKey, error) {
	rows, err := r.queries().ListAccountSetupKeys(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("list setup keys of account %s: %v", accountID, err)
		return nil, status.Errorf(status.Internal, "list setup keys")
	}
	keys := make([]*types.SetupKey, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, toSetupKey(row))
	}
	return keys, nil
}

// Create stores a new setup key.
func (r *SetupKeyRepository) Create(ctx context.Context, key *types.SetupKey) error {
	if err := r.queries().CreateSetupKey(ctx, fromSetupKey(key)); err != nil {
		log.WithContext(ctx).Errorf("create setup key %s: %v", key.Id, err)
		return status.Errorf(status.Internal, "create setup key")
	}
	return nil
}

// IncrementUsage counts one more registration with the key at usedAt.
func (r *SetupKeyRepository) IncrementUsage(ctx context.Context, accountID, id string, usedAt time.Time) error {
	rows, err := r.queries().IncrementSetupKeyUsage(ctx, gen.IncrementSetupKeyUsageParams{
		AccountID: accountID,
		ID:        id,
		LastUsed:  sql.NullTime{Time: usedAt, Valid: true},
	})
	if err != nil {
		log.WithContext(ctx).Errorf("increment usage of setup key %s: %v", id, err)
		return status.Errorf(status.Internal, "increment setup key usage")
	}
	if rows == 0 {
		return status.NewSetupKeyNotFoundError(id)
	}
	return nil
}

// Delete removes the setup key of the account.
func (r *SetupKeyRepository) Delete(ctx context.Context, accountID, id string) error {
	rows, err := r.queries().DeleteSetupKey(ctx, gen.DeleteSetupKeyParams{AccountID: accountID, ID: id})
	if err != nil {
		log.WithContext(ctx).Errorf("delete setup key %s: %v", id, err)
		return status.Errorf(status.Internal, "delete setup key")
	}
	if rows == 0 {
		return status.NewSetupKeyNotFoundError(id)
	}
	return nil
}

func toSetupKey(row gen.SetupKey) *types.SetupKey {
	return &types.SetupKey{
		Id:                  row.ID,
		AccountID:           row.AccountID,
		Key:                 row.Key,
		KeySecret:           row.KeySecret,
		Name:                row.Name,
		Type:                types.SetupKeyType(row.Type),
		CreatedAt:           row.CreatedAt,
		ExpiresAt:           nullableTime(row.ExpiresAt),
		UpdatedAt:           row.UpdatedAt,
		Revoked:             row.Revoked,
		UsedTimes:           int(row.UsedTimes),
		LastUsed:            nullableTime(row.LastUsed),
		AutoGroups:          []string(row.AutoGroups),
		UsageLimit:          int(row.UsageLimit),
		Ephemeral:           row.Ephemeral,
		AllowExtraDNSLabels: row.AllowExtraDnsLabels,
	}
}

func fromSetupKey(key *types.SetupKey) gen.CreateSetupKeyParams {
	return gen.CreateSetupKeyParams{
		ID:                  key.Id,
		AccountID:           key.AccountID,
		Key:                 key.Key,
		KeySecret:           key.KeySecret,
		Name:                key.Name,
		Type:                string(key.Type),
		CreatedAt:           key.CreatedAt,
		ExpiresAt:           timeValue(key.ExpiresAt),
		UpdatedAt:           key.UpdatedAt,
		Revoked:             key.Revoked,
		UsedTimes:           int64(key.UsedTimes),
		LastUsed:            timeValue(key.LastUsed),
		AutoGroups:          key.AutoGroups,
		UsageLimit:          int64(key.UsageLimit),
		Ephemeral:           key.Ephemeral,
		AllowExtraDnsLabels: key.AllowExtraDNSLabels,
	}
}

func nullableTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time
	return &t
}

func timeValue(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}
