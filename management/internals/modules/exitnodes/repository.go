package exitnodes

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

//go:generate go tool mockgen -package exitnodes -destination=repository_mock.go -source=./repository.go -build_flags=-mod=mod

// Repository persists exit nodes.
type Repository interface {
	WithTx(tx *db.Tx) Repository
	// LockAccount serializes exit node writes of one account until the
	// transaction ends, so concurrent writers re-read each other's rows.
	LockAccount(ctx context.Context, accountID string) error
	ListByAccount(ctx context.Context, lockStrength db.LockingStrength, accountID string) ([]*ExitNode, error)
	GetByID(ctx context.Context, lockStrength db.LockingStrength, accountID, exitNodeID string) (*ExitNode, error)
	Create(ctx context.Context, exitNode *ExitNode) error
	Update(ctx context.Context, exitNode *ExitNode) error
	Delete(ctx context.Context, accountID, exitNodeID string) error
}
