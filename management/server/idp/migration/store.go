package migration

import (
	"context"

	"github.com/netbirdio/netbird/management/server/types"
)

// MigrationStore defines the data store operations required for IdP user migration.
// This interface is separate from the main store.Store interface because these methods
// are only used during one-time migration and should be removed once migration tooling
// is no longer needed.
//
// The SQL store implementations (SqlStore) already have these methods on their concrete
// types, so they satisfy this interface via Go's structural typing with zero code changes.
type MigrationStore interface {
	// ListUsers returns all users across all accounts.
	ListUsers(ctx context.Context) ([]*types.User, error)

	// UpdateUserID atomically updates a user's ID and all foreign key references
	// across the database (peers, groups, policies, PATs, etc.).
	UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
}

// MigrationEventStore defines the activity event store operations required for migration.
// Like MigrationStore, this is a temporary interface for migration tooling only.
type MigrationEventStore interface {
	// UpdateUserID updates all event references (initiator_id, target_id) and
	// deleted_users records to use the new user ID format.
	UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
}
