package ipcauth

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/client/proto"
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

// RequireHolderForFullStatus escalates a StatusRequest that asks for peer detail
// or for probes to be run.
func RequireHolderForFullStatus(r Request) error {
	statusReq, ok := r.Msg.(*proto.StatusRequest)
	if !ok {
		return nil
	}
	if r.Level < AuthzLevelSessionHolder {
		if statusReq.GetFullPeerStatus {
			statusReq.GetFullPeerStatus = false
		}
		if statusReq.ShouldRunProbes {
			statusReq.ShouldRunProbes = false
		}
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

func denyLevel(r Request, want AuthzLevel) error {
	return status.Errorf(codes.PermissionDenied,
		"%s requires %s, caller %s is %s", r.Method, want, r.Identity, r.Level)
}

// denyPolicyLevel refuses a caller at the gate, where the policy is in hand.
//
// Requiring privilege is the one denial a caller can act on, so it carries the
// elevated command rather than a bare refusal. A privileged method that declares
// no action keeps the plain message. Rules deny through denyLevel instead: they
// cannot reach the policy table without an initialization cycle, and no rule
// requires privilege.
func denyPolicyLevel(r Request, p MethodPolicy) error {
	switch p.Level {
	case AuthzLevelPrivileged:
		if p.Action != "" {
			actor, command := RequiredActor(p.Command)
			return PrivilegeError(PrivilegeSummary(p.Action, actor), command)
		}

	case AuthzLevelSessionHolder:
		// resolveLevel stops at profile owner only when a session is running and
		// somebody else holds it.
		if r.Level == AuthzLevelProfileOwner {
			return SessionHeldError(p.Action)
		}
		return NotOwnerError(p.Action)

	case AuthzLevelProfileOwner:
		return NotOwnerError(p.Action)
	}

	return denyLevel(r, p.Level)
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

func (g *AuthzGate) authorize(ctx context.Context, method string, msg any) (context.Context, error) {
	id, ok := CallerIdentity(ctx)
	if !ok {
		log.Warnf("ipc authz: DENY %s, caller identity unavailable", method)
		return ctx, status.Error(codes.PermissionDenied,
			"caller identity could not be verified on the daemon control channel")
	}
	st := g.state()
	if st == nil {
		log.Warnf("ipc authz: DENY %s for %s, daemon state not attached", method, id)
		return ctx, status.Error(codes.Unavailable, "daemon not initialized")
	}
	policy := methodPolicyFor(method)

	// Only a target-scoped method reads a profile off the request. Everything
	// else acts on the active profile, which an empty handle resolves to.
	var handle string
	if policy.TargetsProfile {
		named, ok := targetProfile(msg)
		if !ok {
			return ctx, status.Errorf(codes.Internal, "%s is declared target-scoped but names no profile", method)
		}
		handle = named
	}

	target, handleErr := st.ResolveTarget(id, handle)

	level := resolveLevel(id, target, st)

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
