package migration

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/server/types"
)

// SchemaCheck represents a table and the columns required on it.
type SchemaCheck struct {
	Table   string
	Columns []string
}

// RequiredSchema lists all tables and columns that the migration tool needs.
// If any are missing, the user must upgrade their management server first so
// that the automatic GORM migrations create them.
var RequiredSchema = []SchemaCheck{
	{Table: "users", Columns: []string{"id", "email", "name", "account_id"}},
	{Table: "personal_access_tokens", Columns: []string{"user_id", "created_by"}},
	{Table: "peers", Columns: []string{"user_id"}},
	{Table: "accounts", Columns: []string{"created_by"}},
	{Table: "user_invites", Columns: []string{"created_by"}},
	{Table: "proxy_access_tokens", Columns: []string{"created_by"}},
	{Table: "jobs", Columns: []string{"triggered_by"}},
}

// SchemaError describes a single missing table or column.
type SchemaError struct {
	Table  string
	Column string // empty when the whole table is missing
}

func (e SchemaError) String() string {
	if e.Column == "" {
		return fmt.Sprintf("table %q is missing", e.Table)
	}
	return fmt.Sprintf("column %q on table %q is missing", e.Column, e.Table)
}

// Store defines the data store operations required for IdP user migration.
// This interface is separate from the main store.Store interface because these methods
// are only used during one-time migration and should be removed once migration tooling
// is no longer needed.
//
// The SQL store implementations (SqlStore) already have these methods on their concrete
// types, so they satisfy this interface via Go's structural typing with zero code changes.
type Store interface {
	// ListUsers returns all users across all accounts.
	ListUsers(ctx context.Context) ([]*types.User, error)

	// UpdateUserID atomically updates a user's ID and all foreign key references
	// across the database (peers, groups, policies, PATs, etc.).
	UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error

	// UpdateUserInfo updates a user's email and name in the store.
	UpdateUserInfo(ctx context.Context, userID, email, name string) error

	// CheckSchema verifies that all tables and columns required by the migration
	// exist in the database. Returns a list of problems; an empty slice means OK.
	CheckSchema(checks []SchemaCheck) []SchemaError
}

// RequiredEventSchema lists all tables and columns that the migration tool needs
// in the activity/event store.
var RequiredEventSchema = []SchemaCheck{
	{Table: "events", Columns: []string{"initiator_id", "target_id"}},
	{Table: "deleted_users", Columns: []string{"id"}},
}

// EventStore defines the activity event store operations required for migration.
// Like Store, this is a temporary interface for migration tooling only.
type EventStore interface {
	// CheckSchema verifies that all tables and columns required by the migration
	// exist in the event database. Returns a list of problems; an empty slice means OK.
	CheckSchema(checks []SchemaCheck) []SchemaError

	// UpdateUserID updates all event references (initiator_id, target_id) and
	// deleted_users records to use the new user ID format.
	UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
}
