package entra_device_auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	entrajoin "github.com/netbirdio/netbird/management/server/http/handlers/entra_join"
	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
)

// DBProvider is the minimal interface our wiring needs to access the
// management SQL store. *store.SqlStore satisfies it via GetDB().
type DBProvider interface {
	GetDB() *gorm.DB
}

// Wiring bundles the two routers the integration needs to register handlers
// on, plus the dependencies shared between them.
type Wiring struct {
	// RootRouter is the unauthenticated router where /join/entra is mounted.
	RootRouter *mux.Router
	// AdminRouter is the authenticated /api subrouter where CRUD endpoints go.
	AdminRouter *mux.Router

	// DB is the main management gorm connection; used for SQL-backed storage.
	// Typically constructed as `accountManager.GetStore().(DBProvider)`.
	DB DBProvider

	// PeerEnroller hooks the integration into the account manager so it can
	// actually create peers after resolving the mapping.
	PeerEnroller ed.PeerEnroller

	// Permissions is the existing permissions manager. Optional; if nil the
	// admin endpoints will permit any authenticated user — unsafe in prod.
	Permissions permissions.Manager
}

// Install wires both the enrolment (/join/entra) and admin (/api/integrations/entra-device-auth)
// routes and returns the entra_device.Manager in case the caller wants to
// reference it elsewhere (e.g. for the gRPC bootstrap-token validation hook).
func Install(w Wiring) (*ed.Manager, error) {
	if w.RootRouter == nil {
		return nil, fmt.Errorf("entra_device_auth.Install: RootRouter is nil")
	}
	if w.AdminRouter == nil {
		return nil, fmt.Errorf("entra_device_auth.Install: AdminRouter is nil")
	}
	if w.DB == nil {
		return nil, fmt.Errorf("entra_device_auth.Install: DB is nil")
	}
	if w.PeerEnroller == nil {
		return nil, fmt.Errorf("entra_device_auth.Install: PeerEnroller is nil")
	}

	store, err := ed.NewSQLStore(w.DB.GetDB())
	if err != nil {
		return nil, fmt.Errorf("create entra device auth store: %w", err)
	}

	manager := ed.NewManager(store)
	manager.PeerEnroller = w.PeerEnroller

	// Device-facing routes under /join/entra (unauthenticated; device cert is
	// the credential).
	joinHandler := entrajoin.NewHandler(manager)
	joinHandler.Register(w.RootRouter)

	// Admin routes under /api/integrations/entra-device-auth (authenticated;
	// enforced by the shared auth middleware + our local permission check).
	adminHandler := &Handler{
		Store:       store,
		ResolveAuth: resolveUserAuthFromRequest,
		Permit:      buildPermissionChecker(w.Permissions),
	}
	adminHandler.Register(w.AdminRouter)

	return manager, nil
}

// resolveUserAuthFromRequest reads accountID + userID from the context set by
// the existing management auth middleware.
func resolveUserAuthFromRequest(r *http.Request) (string, string, error) {
	ua, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		return "", "", err
	}
	return ua.AccountId, ua.UserId, nil
}

// buildPermissionChecker adapts the generic permissions manager interface to
// the handler's PermissionChecker signature. If the manager is nil, returns a
// checker that always permits (intended for tests / initial bring-up only).
func buildPermissionChecker(pm permissions.Manager) PermissionChecker {
	if pm == nil {
		return func(context.Context, string, string, string) (bool, error) {
			return true, nil
		}
	}
	return func(ctx context.Context, accountID, userID, op string) (bool, error) {
		return pm.ValidateUserPermissions(ctx, accountID, userID, modules.EntraDeviceAuth, mapOperation(op))
	}
}

// mapOperation maps the handler's string op names onto the permissions
// package's strong-typed operation enum.
func mapOperation(op string) operations.Operation {
	switch op {
	case "create":
		return operations.Create
	case "update":
		return operations.Update
	case "delete":
		return operations.Delete
	default:
		return operations.Read
	}
}
