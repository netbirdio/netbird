package ipcauth

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Interceptor enforces per-RPC authorization on the daemon control channel,
// keyed to the caller's kernel-authenticated identity. It is safe-by-default:
// any RPC without a matching bypass is gated by the active profile's ownership,
// and a caller without a readable identity is denied.
type Interceptor struct {
	policy   ProfilePolicy
	resolver GroupResolver
	// selfUID is the daemon's own effective UID. A caller whose UID matches it
	// (rootless container / foreground daemon running as the invoking user) is
	// allowed: it already has full control of the daemon process. -1 on Windows.
	selfUID int
}

// NewInterceptor builds an interceptor over the given policy and group resolver.
func NewInterceptor(policy ProfilePolicy, resolver GroupResolver) *Interceptor {
	return &Interceptor{policy: policy, resolver: resolver, selfUID: os.Geteuid()}
}

// UnaryServerInterceptor authorizes each unary RPC before the handler runs.
func (i *Interceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := i.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor authorizes each streaming RPC before the handler runs.
func (i *Interceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := i.authorize(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func (i *Interceptor) authorize(ctx context.Context, fullMethod string) error {
	id, ok := IdentityFromContext(ctx)
	if !ok {
		log.Warnf("ipc authz: DENY %s — caller identity unavailable", fullMethod)
		return status.Error(codes.PermissionDenied, "caller identity could not be verified on the daemon control channel")
	}

	if i.isSelfOrPrivileged(id) {
		// The local JSON gateway connects as the daemon itself (self/privileged)
		// and forwards the real HTTP client's identity. Trust it here — and only
		// here, where the transport peer is already the daemon — then authorize
		// as the forwarded client. A direct non-privileged caller never reaches
		// this branch, so it cannot forge the forwarding metadata.
		fwd, hasFwd := forwardedIdentity(ctx)
		if !hasFwd {
			i.auditAllow(id, fullMethod)
			return nil
		}
		log.Infof("ipc authz: honoring gateway-forwarded identity %s", fwd)
		id = fwd
		if i.isSelfOrPrivileged(id) {
			i.auditAllow(id, fullMethod)
			return nil
		}
	}

	// Per-user / per-target-profile RPCs authorize themselves in the handler.
	if handlerAuthorizedMethods[fullMethod] {
		return nil
	}

	o := i.policy.ActiveProfileOwnership()

	// Trust-on-first-use: an unowned, non-shared profile is claimed by the first
	// caller. The claim is atomic; if we lose the race we re-read and authorize.
	if len(o.Owners) == 0 && !o.Shared {
		claimed, err := i.policy.ClaimActiveProfileOwnerIfUnowned(id)
		if err != nil {
			log.Errorf("ipc authz: claim active profile for %s: %v", id, err)
			return status.Error(codes.Internal, "failed to claim profile ownership")
		}
		if claimed {
			log.Infof("ipc authz: %s claimed ownership of the active profile (trust-on-first-use)", id)
			i.auditAllow(id, fullMethod)
			return nil
		}
		o = i.policy.ActiveProfileOwnership()
	}

	if Authorize(o, id, i.resolver) {
		i.auditAllow(id, fullMethod)
		return nil
	}

	log.Warnf("ipc authz: DENY %s for %s — active profile owned by another principal", fullMethod, id)
	return status.Errorf(codes.PermissionDenied,
		"not authorized to control the active profile (caller %s); ask an owner or run as root/administrator", id)
}

// isSelfOrPrivileged reports whether the caller is the platform administrator
// (root / elevated-admin / LocalSystem) or the daemon's own user.
func (i *Interceptor) isSelfOrPrivileged(id Identity) bool {
	if id.IsPrivileged() {
		return true
	}
	// Daemon-self: only meaningful on Unix (Windows privilege is covered above).
	return !id.IsWindows() && i.selfUID >= 0 && int(id.UID) == i.selfUID
}

func (i *Interceptor) auditAllow(id Identity, fullMethod string) {
	if auditMethods[fullMethod] {
		log.Infof("ipc authz: allow %s for %s", fullMethod, id)
	}
}
