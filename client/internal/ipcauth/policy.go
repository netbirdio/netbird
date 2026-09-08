package ipcauth

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DaemonState interface {
	// SessionHolder returns the principal entitled to the live connection and
	// whether one is held. A held session whose owner cannot be parsed returns
	// the zero Principal with true, which matches nobody, so a corrupt owner
	// field locks the session instead of opening it.
	SessionHolder() (Principal, bool)
}

type Rule func(id Identity, st DaemonState) error

type RuleGate struct {
	mu    sync.Mutex
	rules []Rule
	st    DaemonState
}

func NewRuleGate() *RuleGate {
	return &RuleGate{}
}

func (g *RuleGate) SetState(st DaemonState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.st = st
}

func (g *RuleGate) SetRule(r Rule) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rules = append(g.rules, r)
}

func (g *RuleGate) state() DaemonState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st
}

// RequireSessionHolder allows the caller to act on the live connection. With no
// session held there is nothing to protect, and root can always take over.
func RequireSessionHolder(id Identity, st DaemonState) error {
	holder, running := st.SessionHolder()
	if !running || IsPrivilegedCaller(id) || holder.Matches(id) {
		return nil
	}
	log.Debugf("caller %v is not the session holder %v", id, holder)
	return status.Errorf(codes.PermissionDenied, "session is held by another user (%v)", holder)
}

func (g *RuleGate) StreamPolicyInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if authErr := g.authorize(ss.Context()); authErr != nil {
			return authErr
		}
		return handler(ss.Context(), ss)
	}
}

func (g *RuleGate) UnaryPolicyInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if authErr := g.authorize(ctx); authErr != nil {
			return nil, authErr
		}
		return handler(ctx, req)
	}
}

func (g *RuleGate) authorize(ctx context.Context) error {
	id, ok := CallerIdentity(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "caller cannot be verified")
	}
	state := g.state()
	for _, rule := range g.rules {
		ruleErr := rule(id, state)
		if ruleErr != nil {
			return ruleErr
		}
	}
	return nil
}
