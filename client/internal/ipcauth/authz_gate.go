package ipcauth

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// DaemonState is used to surface the server state needed for determining
// authorization.
type DaemonState interface {
	// SessionHolder returns the principal entitled to the live connection and
	// whether one is held.
	SessionHolder() (Principal, bool)

	// ResolveTarget resolves the profile a request names to a concrete profile
	// and reports whether the caller may address it. An empty handle is the
	// active profile.
	//
	// The error says what was wrong with the handle itself.
	ResolveTarget(id Identity, handle string) (Target, error)
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

// StreamPolicyInterceptor authorizes each streaming RPC before the handler runs.
// The request payload is not yet available, so no streaming method may be
// target-scoped.
func (g *AuthzGate) StreamPolicyInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// A stream's context cannot be replaced from here. We use context to pass
		// resolved target profile and no streaming method may be target-scoped.
		if _, authErr := g.authorize(ss.Context(), info.FullMethod, nil); authErr != nil {
			return authErr
		}
		return handler(srv, ss)
	}
}

// UnaryPolicyInterceptor authorizes each unary RPC before the handler runs.
func (g *AuthzGate) UnaryPolicyInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		ctx, authErr := g.authorize(ctx, info.FullMethod, req)
		if authErr != nil {
			return nil, authErr
		}
		return handler(ctx, req)
	}
}

// resolveLevel is the authority the caller holds over the profile the request
// resolved to. A profile the caller does not own confers nothing beyond being
// identified, which is also what an unresolved handle leaves them with.
func (g *AuthzGate) resolveLevel(id Identity, target Target) AuthzLevel {
	if !id.Known() {
		return AuthzLevelNone
	}
	if IsPrivilegedCaller(id) {
		return AuthzLevelPrivileged
	}
	if !target.Owned {
		return AuthzLevelIdentified
	}
	if holder, running := g.st.SessionHolder(); !running || holder.Matches(id) {
		return AuthzLevelSessionHolder
	}
	return AuthzLevelProfileOwner
}

func (g *AuthzGate) authorize(ctx context.Context, method string, msg any) (context.Context, error) {
	id, ok := CallerIdentity(ctx)
	if !ok {
		log.Warnf("ipc authz: DENY %s, caller identity unavailable", method)
		return ctx, gstatus.Error(codes.PermissionDenied,
			"caller identity could not be verified on the daemon control channel")
	}
	st := g.state()
	if st == nil {
		log.Warnf("ipc authz: DENY %s for %s, daemon state not attached", method, id)
		return ctx, gstatus.Error(codes.Unavailable, "daemon not initialized")
	}
	policy := methodPolicyFor(method)

	// Only a target-scoped method reads a profile off the request. Everything
	// else acts on the active profile, which an empty handle resolves to.
	var handle string
	if policy.TargetsProfile {
		named, ok := targetProfile(msg)
		if !ok {
			return ctx, gstatus.Errorf(codes.Internal, "%s is declared target-scoped but names no profile", method)
		}
		handle = named
	}

	target, handleErr := st.ResolveTarget(id, handle)

	level := g.resolveLevel(id, target)

	if handleErr != nil && handle != "" {
		level = AuthzLevelIdentified
	}

	req := Request{
		Identity: id,
		Level:    level,
		Target:   handle,
		Method:   method,
		State:    st,
		Msg:      msg,
	}
	if req.Level < policy.Level {
		log.Warnf("ipc authz: DENY %s for %s (%s), requires %s", method, id, req.Level, policy.Level)
		if presentable := presentableHandleError(handle, handleErr); presentable != nil {
			return ctx, presentable
		}
		return ctx, denyPolicyLevel(req, policy)
	}
	for _, rule := range policy.Rules {
		if err := rule(req); err != nil {
			log.Warnf("ipc authz: DENY %s for %s (%s): error", method, id, req.Level)
			return ctx, err
		}
	}
	if policy.Audit {
		log.Infof("ipc authz: allow %s for %s (%s)", method, id, req.Level)
	}
	if !target.Owned {
		// Reaching here means the method was open to the caller's level
		// without owning anything, so there is no authorized profile to hand
		// the handler.
		return ctx, nil
	}
	return ContextWithTarget(ctx, target.Path), nil
}

// presentableHandleError keeps a resolution failure only when the gate can put
// it in front of the caller in place of its own refusal. Everything else is
// dropped, and the caller gets the refusal their level earned.
func presentableHandleError(handle string, err error) error {
	if err == nil {
		return nil
	}

	// An empty handle is the active profile rather than something the caller
	// typed, so a failure to resolve it is not theirs to correct.
	if handle == "" {
		return nil
	}

	// Only a gRPC status reaches the caller as a sentence the CLI and the UI
	// render. A plain error is a daemon-side failure, and putting it on the
	// wire would tell the caller about the daemon rather than about the handle
	// they gave.
	if _, ok := gstatus.FromError(err); !ok {
		return nil
	}
	return err
}
