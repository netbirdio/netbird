package roles

import (
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
)

// BillingAdmin manages plans, seats, and invoices, which are enforced
// outside this permission map (NetBird Cloud). Management-side it carries
// the regular User baseline; the explicit entry keeps role resolution from
// failing with a role-not-found error.
var BillingAdmin = RolePermissions{
	Role: types.UserRoleBillingAdmin,
	AutoAllowNew: map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	},
}
