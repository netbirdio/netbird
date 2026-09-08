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

// RequireHolderForFullStatus is a Rule that enforces the right AuthzLevel if
// "full status" or "should run probes" are requested in a StatusRequest.
func RequireHolderForFullStatus(r Request) error {
	full, ok := r.Msg.(interface{ GetGetFullPeerStatus() bool })
	if !ok || !full.GetGetFullPeerStatus() {
		return nil
	}
	probes, ok := r.Msg.(interface{ ShouldRunProbes() bool })
	if !ok || !probes.ShouldRunProbes() {
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
	return status.Error(codes.Unimplemented, "pending flows are not yet caller-bound")
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
		authCtx, authErr := g.authorize(ss.Context(), info.FullMethod, nil)
		if authErr != nil {
			return authErr
		}
		return handler(srv, &authorizedStream{ServerStream: ss, ctx: authCtx})
	}
}

// UnaryPolicyInterceptor authorizes each unary RPC before the handler runs.
func (g *AuthzGate) UnaryPolicyInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		authCtx, authErr := g.authorize(ctx, info.FullMethod, req)
		if authErr != nil {
			return nil, authErr
		}
		return handler(authCtx, req)
	}
}

func (g *AuthzGate) authorize(ctx context.Context, method string, msg any) (context.Context, error) {
	id, ok := CallerIdentity(ctx)
	if !ok {
		log.Warnf("ipc authz: DENY %s, caller identity unavailable", method)
		return nil, status.Error(codes.PermissionDenied,
			"caller identity could not be verified on the daemon control channel")
	}
	st := g.state()
	if st == nil {
		log.Warnf("ipc authz: DENY %s for %s, daemon state not attached", method, id)
		return nil, status.Error(codes.Unavailable, "daemon not initialized")
	}
	target, named := targetProfile(msg)
	policy := methodPolicyFor(method)
	if policy.TargetsProfile && !named {
		return nil, status.Errorf(codes.Internal, "%s is declared target-scoped but names no profile", method)
	}
	auth := Authorization{
		Identity: id,
		Level:    resolveLevel(id, target, st),
		Target:   target,
		Method:   method,
	}
	req := Request{Authorization: auth, State: st, Msg: msg}
	if req.Level < policy.Level {
		log.Warnf("ipc authz: DENY %s for %s (%s), requires %s", method, id, req.Level, policy.Level)
		return nil, denyLevel(req, policy.Level)
	}
	for _, rule := range policy.Rules {
		if err := rule(req); err != nil {
			log.Warnf("ipc authz: DENY %s for %s (%s): %v", method, id, req.Level, err)
			return nil, err
		}
	}
	if policy.Audit {
		log.Infof("ipc authz: allow %s for %s (%s)", method, id, req.Level)
	}
	return withAuthorization(ctx, auth), nil
}

// authorizedStream carries the authorized context into a streaming handler,
// which would otherwise see the one the stream was created with.
type authorizedStream struct {
	grpc.ServerStream
	ctx context.Context
}

type authorizationKey struct{}

func withAuthorization(ctx context.Context, a Authorization) context.Context {
	return context.WithValue(ctx, authorizationKey{}, a)
}

// Authorized returns the decision the interceptor made for this RPC.
//
// Read it to decide what a caller sees or who an action is attributed to. Do not
// read it to decide whether a call is allowed, which is the method table's job.
func Authorized(ctx context.Context) Authorization {
	a, _ := ctx.Value(authorizationKey{}).(Authorization)
	return a
}
