package store

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
)

// TestPgxServiceColumnsMatchGorm guards the Postgres pgx read path against
// drifting from the gorm model. The SQLite/MySQL gorm path loads rows by struct,
// so a new column on a model is picked up automatically, but the hand-written
// pgx SELECT in sql_store.go must be updated by hand. This test fails when a
// gorm column is missing from the pgx column list, which otherwise silently
// returns zero-valued on Postgres with no compile error.
func TestPgxServiceColumnsMatchGorm(t *testing.T) {
	tests := []struct {
		name          string
		model         any
		selectColumns string
		// excluded lists gorm columns intentionally not loaded by the pgx path.
		excluded map[string]struct{}
	}{
		{
			name:          "service",
			model:         &rpservice.Service{},
			selectColumns: serviceSelectColumns,
		},
		{
			name:          "target",
			model:         &rpservice.Target{},
			selectColumns: targetSelectColumns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			selected := parseColumnList(tc.selectColumns)
			for _, col := range gormColumnNames(t, tc.model) {
				if _, ok := tc.excluded[col]; ok {
					continue
				}
				_, ok := selected[col]
				assert.Truef(t, ok,
					"gorm column %q is not read by the Postgres pgx SELECT; add it to %sSelectColumns in sql_store.go (or to the test's excluded set if it is intentionally not loaded)",
					col, tc.name)
			}
		})
	}
}

func parseColumnList(cols string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, c := range strings.Split(cols, ",") {
		if c = strings.TrimSpace(c); c != "" {
			set[c] = struct{}{}
		}
	}
	return set
}

// gormColumnNames returns the DB column names gorm would migrate for the model,
// using the same default naming strategy the store configures.
func gormColumnNames(t *testing.T, model any) []string {
	t.Helper()
	sch, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
	require.NoError(t, err)
	return sch.DBNames
}
