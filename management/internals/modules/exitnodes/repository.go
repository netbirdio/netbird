package exitnodes

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

//go:generate go tool mockgen -package exitnodes -destination=repository_mock.go -source=./repository.go -build_flags=-mod=mod

// Repository persists exit nodes and their peers.
type Repository interface {
	WithTx(tx *db.Tx) Repository
	// LockAccount locks the account row until the transaction ends, so the exit node writes
	// of one account run one at a time. Run it in a transaction.
	LockAccount(ctx context.Context, accountID string) error
	ListByAccount(ctx context.Context, lockStrength db.LockingStrength, accountID string) ([]*ExitNode, error)
	Get(ctx context.Context, lockStrength db.LockingStrength, accountID string, exitNodeID ID) (*ExitNode, error)
	// Create inserts the exit node and its peers. Run it in a transaction.
	Create(ctx context.Context, exitNode *ExitNode) error
	// Update replaces the exit node and its peers. Run it in a transaction.
	Update(ctx context.Context, exitNode *ExitNode) error
	// Delete removes the exit node and its peers. Run it in a transaction.
	Delete(ctx context.Context, accountID string, exitNodeID ID) error
}
