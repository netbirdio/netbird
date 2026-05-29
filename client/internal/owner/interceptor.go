package owner

import (
	"context"
	"slices"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/owner/consoleuser"
)

const servicePath = "/daemon.DaemonService/"

// profileBypassMethods skip the active-profile owner check. They either
// operate on a specific target profile (and the handler enforces target-profile
// owner-or-root itself) or are per-user listings/creations that don't affect
// the active session and shouldn't require active-profile ownership. Peer
// credentials are still required.
var profileBypassMethods = map[string]bool{
	servicePath + "AddProfile":    true,
	servicePath + "ListProfiles":  true,
	servicePath + "RemoveProfile": true,
	servicePath + "SwitchProfile": true,
}

// Error messages returned to denied callers. They are multi-line so the
// suggested commands sit on their own line for easy triple-click copy-paste.
const (
	errNoPeerCreds = "peer credentials unavailable; rerun via the netbird CLI"

	errNoOwnerConfigured = `no daemon owner is configured and no console-session user matches your UID.
Run as root for one-off use:
    sudo netbird ...
Or call from the active console session: the first call from the user logged in
at the GUI/console claims ownership automatically.`

	errOwnerRequired = `this operation requires root or the daemon owner (uid %d is not an owner).
Run as root for one-off use:
    sudo netbird ...
Or ask an existing owner (or root) to add you:
    sudo netbird owner add %[1]d`
)

// consoleUIDLookup is the function used to look up the active console UID.
// Overridable in tests; defaults to the platform implementation.
var consoleUIDLookup = consoleuser.ActiveUID

// OwnerConfig provides access to the current owner UIDs setting.
// The interceptor reads and writes through this interface so it can
// work with the profile manager's config without a direct dependency.
type OwnerConfig interface {
	// GetOwnerUIDs returns the current owner UIDs.
	// nil means legacy/migration TOFU (field absent from existing config).
	// empty means fresh install (root-only with console-user TOFU exception).
	// populated means those UIDs plus root may control the daemon.
	GetOwnerUIDs() []UID

	// AddOwnerUID adds the given UID to the owner list and persists it.
	AddOwnerUID(uid UID) error
}

// Interceptor enforces owner restrictions on the daemon gRPC socket.
type Interceptor struct {
	config OwnerConfig
	// mu serializes the read-then-write of OwnerUIDs during TOFU/claim flows
	// so two concurrent first-callers can't both end up persisted as owners.
	// Holds across the OwnerConfig.AddOwnerUID call; safe because no callback
	// path takes this mutex.
	mu sync.Mutex
}

// NewInterceptor creates an owner interceptor backed by the given config.
func NewInterceptor(config OwnerConfig) *Interceptor {
	return &Interceptor{config: config}
}

// UnaryInterceptor returns a gRPC unary server interceptor that enforces owner policy.
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := i.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC stream server interceptor that enforces owner policy.
func (i *Interceptor) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := i.authorize(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// authorize checks whether the caller is allowed to call the given method.
// Every RPC is gated; root is always allowed. Non-root callers are accepted
// when they are existing owners, when the config is in legacy TOFU state
// (claim on first call, preserves pre-enforcement behavior), or when the
// config is in fresh-install state and they match the active console user.
func (i *Interceptor) authorize(ctx context.Context, fullMethod string) error {
	uid, ok := UIDFromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, errNoPeerCreds)
	}

	if uid == 0 {
		return nil
	}

	// Profile-management RPCs do their own per-target authorization in the
	// handler. The interceptor only confirms peer credentials are present.
	if profileBypassMethods[fullMethod] {
		return nil
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	ownerUIDs := i.config.GetOwnerUIDs()

	switch {
	case ownerUIDs == nil:
		// Legacy / migration TOFU: existing pre-enforcement config has no
		// owners field. Any non-root local caller claims on first call so
		// upgrades don't break.
		return i.claim(uid, "migration TOFU")

	case len(ownerUIDs) == 0:
		// Fresh-install root-only mode with a console-user exception so the
		// GUI/CLI just works for the user physically at the machine. SSH'd
		// or otherwise non-console callers are denied.
		consoleUID, ok := consoleUIDLookup()
		if ok && uint32(uid) == consoleUID {
			return i.claim(uid, "console-user TOFU")
		}
		return status.Error(codes.PermissionDenied, errNoOwnerConfigured)

	case slices.Contains(ownerUIDs, uid):
		return nil

	default:
		return status.Errorf(codes.PermissionDenied, errOwnerRequired, uid)
	}
}

// claim adds uid to the owner list and persists it. The caller must hold i.mu.
func (i *Interceptor) claim(uid UID, reason string) error {
	log.Infof("%s: claiming owner for UID %d", reason, uid)
	if err := i.config.AddOwnerUID(uid); err != nil {
		log.Errorf("persist owner UID: %v", err)
		return status.Error(codes.Internal, "persist owner UID")
	}
	return nil
}
