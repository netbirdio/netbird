package grpc

import (
	"context"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	// lastUsedUpdateInterval is the minimum interval between last_used updates for the same token.
	lastUsedUpdateInterval = time.Minute
	// lastUsedCleanupInterval is how often stale lastUsed entries are removed.
	lastUsedCleanupInterval = 2 * time.Minute
)

type proxyTokenContextKey struct{}

// ProxyTokenContextKey is the typed key used to store validated token info in context.
var ProxyTokenContextKey = proxyTokenContextKey{}

// proxyTokenID identifies a proxy access token by its database ID.
type proxyTokenID = string

// proxyTokenStore defines the store interface needed for token validation
type proxyTokenStore interface {
	GetProxyAccessTokenByHashedToken(ctx context.Context, lockStrength store.LockingStrength, hashedToken types.HashedProxyToken) (*types.ProxyAccessToken, error)
	MarkProxyAccessTokenUsed(ctx context.Context, tokenID string) error
}

// proxyAuthInterceptor holds state for proxy authentication interceptors.
type proxyAuthInterceptor struct {
	store          proxyTokenStore
	failureLimiter *authFailureLimiter

	// lastUsedMu protects lastUsedTimes
	lastUsedMu    sync.Mutex
	lastUsedTimes map[proxyTokenID]time.Time
	cancel        context.CancelFunc
}

func newProxyAuthInterceptor(tokenStore proxyTokenStore) *proxyAuthInterceptor {
	ctx, cancel := context.WithCancel(context.Background())
	i := &proxyAuthInterceptor{
		store:          tokenStore,
		failureLimiter: newAuthFailureLimiter(),
		lastUsedTimes:  make(map[proxyTokenID]time.Time),
		cancel:         cancel,
	}
	go i.lastUsedCleanupLoop(ctx)
	return i
}

// NewProxyAuthInterceptors creates gRPC unary and stream interceptors that validate proxy access tokens.
// They only intercept ProxyService methods. Both interceptors share state for last-used and failure rate limiting.
// The returned close function must be called on shutdown to stop background goroutines.
func NewProxyAuthInterceptors(tokenStore proxyTokenStore) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor, func()) {
	interceptor := newProxyAuthInterceptor(tokenStore)

	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !strings.HasPrefix(info.FullMethod, "/management.ProxyService/") {
			return handler(ctx, req)
		}

		token, err := interceptor.validateProxyToken(ctx)
		if err != nil {
			// Log auth failures explicitly; gRPC doesn't log these by default.
			log.WithContext(ctx).Warnf("proxy auth failed: %v", err)
			return nil, err
		}

		ctx = context.WithValue(ctx, ProxyTokenContextKey, token)
		return handler(ctx, req)
	}

	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !strings.HasPrefix(info.FullMethod, "/management.ProxyService/") {
			return handler(srv, ss)
		}

		token, err := interceptor.validateProxyToken(ss.Context())
		if err != nil {
			// Log auth failures explicitly; gRPC doesn't log these by default.
			log.WithContext(ss.Context()).Warnf("proxy auth failed: %v", err)
			return err
		}

		ctx := context.WithValue(ss.Context(), ProxyTokenContextKey, token)
		wrapped := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		return handler(srv, wrapped)
	}

	return unary, stream, interceptor.close
}

func (i *proxyAuthInterceptor) validateProxyToken(ctx context.Context) (*types.ProxyAccessToken, error) {
	clientIP := peerIPFromContext(ctx)

	if clientIP != "" && i.failureLimiter.isLimited(clientIP) {
		return nil, status.Errorf(codes.ResourceExhausted, "too many failed authentication attempts")
	}

	token, err := i.doValidateProxyToken(ctx)
	if err != nil {
		if clientIP != "" {
			i.failureLimiter.recordFailure(clientIP)
		}
		return nil, err
	}

	i.maybeUpdateLastUsed(ctx, token.ID)

	return token, nil
}

func (i *proxyAuthInterceptor) doValidateProxyToken(ctx context.Context) (*types.ProxyAccessToken, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	authValues := md.Get("authorization")
	if len(authValues) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing authorization header")
	}

	authValue := authValues[0]
	if !strings.HasPrefix(authValue, "Bearer ") {
		return nil, status.Errorf(codes.Unauthenticated, "invalid authorization format")
	}

	plainToken := types.PlainProxyToken(strings.TrimPrefix(authValue, "Bearer "))

	if err := plainToken.Validate(); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token format")
	}

	token, err := i.store.GetProxyAccessTokenByHashedToken(ctx, store.LockingStrengthNone, plainToken.Hash())
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	// TODO: Enforce AccountID scope for "bring your own proxy" feature.
	// Currently tokens are management-wide; AccountID field is reserved for future use.

	if !token.IsValid() {
		return nil, status.Errorf(codes.Unauthenticated, "token expired or revoked")
	}

	return token, nil
}

// maybeUpdateLastUsed updates the last_used timestamp if enough time has passed since the last update.
func (i *proxyAuthInterceptor) maybeUpdateLastUsed(ctx context.Context, tokenID string) {
	now := time.Now()

	i.lastUsedMu.Lock()
	lastUpdate, exists := i.lastUsedTimes[tokenID]
	if exists && now.Sub(lastUpdate) < lastUsedUpdateInterval {
		i.lastUsedMu.Unlock()
		return
	}
	i.lastUsedTimes[tokenID] = now
	i.lastUsedMu.Unlock()

	if err := i.store.MarkProxyAccessTokenUsed(ctx, tokenID); err != nil {
		log.WithContext(ctx).Debugf("failed to mark proxy token as used: %v", err)
	}
}

func (i *proxyAuthInterceptor) lastUsedCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(lastUsedCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.cleanupStaleLastUsed()
		case <-ctx.Done():
			return
		}
	}
}

// cleanupStaleLastUsed removes entries older than 2x the update interval.
func (i *proxyAuthInterceptor) cleanupStaleLastUsed() {
	i.lastUsedMu.Lock()
	defer i.lastUsedMu.Unlock()

	now := time.Now()
	staleThreshold := 2 * lastUsedUpdateInterval
	for id, lastUpdate := range i.lastUsedTimes {
		if now.Sub(lastUpdate) > staleThreshold {
			delete(i.lastUsedTimes, id)
		}
	}
}

func (i *proxyAuthInterceptor) close() {
	i.cancel()
	i.failureLimiter.stop()
}

// GetProxyTokenFromContext retrieves the validated proxy token from the context
func GetProxyTokenFromContext(ctx context.Context) *types.ProxyAccessToken {
	token, ok := ctx.Value(ProxyTokenContextKey).(*types.ProxyAccessToken)
	if !ok {
		return nil
	}
	return token
}

// wrappedServerStream wraps a grpc.ServerStream to provide a custom context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
