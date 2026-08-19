package ipcauth

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Policy interface {
	SessionHolder() (Identity, bool)
}

type PolicyGate struct {
	mu     sync.Mutex
	policy Policy
}

func NewPolicyGate() *PolicyGate {
	return &PolicyGate{}
}

func (g *PolicyGate) SetPolicy(p Policy) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policy = p
}

func (g *PolicyGate) SessionHolder() (Identity, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.policy == nil {
		return Identity{}, false
	}
	return g.policy.SessionHolder()
}

func (g *PolicyGate) StreamPolicyInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !g.authorize(ss.Context()) {
			return status.Error(codes.PermissionDenied, "caller is not session owner")
		}
		return handler(ss.Context(), ss)
	}
}

func (g *PolicyGate) UnaryPolicyInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if !g.authorize(ctx) {
			return nil, status.Error(codes.PermissionDenied, "caller is not session owner")
		}
		return handler(ctx, req)
	}
}

func (g *PolicyGate) authorize(ctx context.Context) bool {
	id, ok := CallerIdentity(ctx)
	if !ok {
		return false
	}
	g.mu.Lock()
	if g.policy == nil {
		g.mu.Unlock()
		return false
	}
	sessionId, running := g.policy.SessionHolder()
	// TODO improve logging
	log.Infof("id : %v, session holder: %v", id, sessionId)
	g.mu.Unlock()
	// TODO windows
	// TODO allow root
	if running && sessionId.UID != id.UID {
		return false
	}
	return true
}
