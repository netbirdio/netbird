package server

import (
	"context"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// validateGroupResources ensures every network resource referenced by the group
// exists in the account. Without this check the groups endpoint silently accepts
// non-existent resource IDs, leaving the group pointing at resources that never
// show up in the dashboard (see issue #3495).
func validateGroupResources(ctx context.Context, transaction store.Store, accountID string, resources []types.Resource) error {
	for _, resource := range resources {
		if _, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, resource.ID); err != nil {
			return err
		}
	}
	return nil
}
