package ipcauth

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DaemonState is used to surface the server state needed for determining
// authorization.
type DaemonState interface {
	// SessionHolder returns the principal entitled to the live connection and
	// whether one is held.
	SessionHolder() (Principal, bool)

	OwnsProfile(id Identity, handle string) bool
}

// AuthzGate authorizes every RPC call before its handler run.
type AuthzGate struct {
	mu sync.Mutex
	st DaemonState
}

// NewAuthzGate returns a gate with no state attached.
func NewAuthzGate() *AuthzGate {
	return &AuthzGate{}
}

// SetState attaches the daemon state. Musy be called before serving RPCs.
func (g *AuthzGate) SetState(st DaemonState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.st = st
}

func (g *AuthzGate) state() DaemonState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st
}

// RequireHolderForFullStatus escalates a StatusRequest that asks for peer detail
// or for probes to be run.
func RequireHolderForFullStatus(r Request) error {
	statusReq, ok := r.Msg.(interface {
		GetGetFullPeerStatus() bool
		GetShouldRunProbes() bool
	})
	if !ok {
		return nil
	}
	if !statusReq.GetGetFullPeerStatus() && !statusReq.GetShouldRunProbes() {
		return nil
	}
	return RequireLevel(AuthzLevelSessionHolder)(r)
}

// RequireLevel builds a rule from a level, for composing inside another rule.
func RequireLevel(want AuthzLevel) Rule {
	return func(r Request) error {
		if r.Level >= want {
			return nil
		}
		return denyLevel(r, want)
	}
}

// RequireFlowInitiator binds a pending authentication flow to the identity that
// started it.
func RequireFlowInitiator(r Request) error {
	// TODO: needs the flow registry keyed by initiator.
	return nil
}

func denyLevel(r Request, want AuthzLevel) error {
	return status.Errorf(codes.PermissionDenied,
		"%s requires %s, caller %s is %s", r.Method, want, r.Identity, r.Level)
}

// StreamPolicyInterceptor authorizes each streaming RPC before the handler runs.
// The request payload is not yet available, so no streaming method may be
// target-scoped.
func (g *AuthzGate) StreamPolicyInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authErr := g.authorize(ss.Context(), info.FullMethod, nil)
		if authErr != nil {
			return authErr
		}
		return handler(srv, ss)
	}
}

// UnaryPolicyInterceptor authorizes each unary RPC before the handler runs.
func (g *AuthzGate) UnaryPolicyInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		authErr := g.authorize(ctx, info.FullMethod, req)
		if authErr != nil {
			return nil, authErr
		}
		return handler(ctx, req)
	}
}

func (g *AuthzGate) authorize(ctx context.Context, method string, msg any) error {
	id, ok := CallerIdentity(ctx)
	if !ok {
		log.Warnf("ipc authz: DENY %s, caller identity unavailable", method)
		return status.Error(codes.PermissionDenied,
			"caller identity could not be verified on the daemon control channel")
	}
	st := g.state()
	if st == nil {
		log.Warnf("ipc authz: DENY %s for %s, daemon state not attached", method, id)
		return status.Error(codes.Unavailable, "daemon not initialized")
	}
	policy := methodPolicyFor(method)

	// Only a target-scoped method reads a profile off the request.
	var target string
	if policy.TargetsProfile {
		named, ok := targetProfile(msg)
		if !ok {
			return status.Errorf(codes.Internal, "%s is declared target-scoped but names no profile", method)
		}
		target = named
	}

	req := Request{
		Identity: id,
		Level:    resolveLevel(id, target, st),
		Target:   target,
		Method:   method,
		State:    st,
		Msg:      msg,
	}
	if req.Level < policy.Level {
		log.Warnf("ipc authz: DENY %s for %s (%s), requires %s", method, id, req.Level, policy.Level)
		return denyLevel(req, policy.Level)
	}
	for _, rule := range policy.Rules {
		if err := rule(req); err != nil {
			log.Warnf("ipc authz: DENY %s for %s (%s): %v", method, id, req.Level, err)
			return err
		}
	}
	if policy.Audit {
		log.Infof("ipc authz: allow %s for %s (%s)", method, id, req.Level)
	}
	return nil
}
