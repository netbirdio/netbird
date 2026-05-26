package proxy

import (
	"context"
	"maps"
	"net/netip"
	"sync"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

type requestContextKey string

const (
	capturedDataKey requestContextKey = "capturedData"
)

// ResponseOrigin indicates where a response was generated.
type ResponseOrigin int

const (
	// OriginBackend means the response came from the backend service.
	OriginBackend ResponseOrigin = iota
	// OriginNoRoute means the proxy had no matching host or path.
	OriginNoRoute
	// OriginProxyError means the proxy failed to reach the backend.
	OriginProxyError
	// OriginAuth means the proxy intercepted the request for authentication.
	OriginAuth
)

func (o ResponseOrigin) String() string {
	switch o {
	case OriginNoRoute:
		return "no_route"
	case OriginProxyError:
		return "proxy_error"
	case OriginAuth:
		return "auth"
	default:
		return "backend"
	}
}

// CapturedData is a mutable struct that allows downstream handlers
// to pass data back up the middleware chain.
type CapturedData struct {
	mu         sync.RWMutex
	requestID  string
	serviceID  types.ServiceID
	accountID  types.AccountID
	origin     ResponseOrigin
	clientIP   netip.Addr
	userID     string
	userEmail  string
	userGroups []string
	// userGroupNames pairs positionally with userGroups; populated from
	// the JWT's group_names claim or from ValidateSession/Tunnel
	// responses. Slice may be shorter than userGroups for tokens minted
	// before names were resolvable.
	userGroupNames []string
	authMethod     string
	metadata       map[string]string
}

// NewCapturedData creates a CapturedData with the given request ID.
func NewCapturedData(requestID string) *CapturedData {
	return &CapturedData{requestID: requestID}
}

// GetRequestID returns the request ID.
func (c *CapturedData) GetRequestID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.requestID
}

// SetServiceID sets the service ID.
func (c *CapturedData) SetServiceID(serviceID types.ServiceID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serviceID = serviceID
}

// GetServiceID returns the service ID.
func (c *CapturedData) GetServiceID() types.ServiceID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceID
}

// SetAccountID sets the account ID.
func (c *CapturedData) SetAccountID(accountID types.AccountID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accountID = accountID
}

// GetAccountID returns the account ID.
func (c *CapturedData) GetAccountID() types.AccountID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accountID
}

// SetOrigin sets the response origin.
func (c *CapturedData) SetOrigin(origin ResponseOrigin) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.origin = origin
}

// GetOrigin returns the response origin.
func (c *CapturedData) GetOrigin() ResponseOrigin {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.origin
}

// SetClientIP sets the resolved client IP.
func (c *CapturedData) SetClientIP(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientIP = ip
}

// GetClientIP returns the resolved client IP.
func (c *CapturedData) GetClientIP() netip.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP
}

// SetUserID sets the authenticated user ID.
func (c *CapturedData) SetUserID(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userID = userID
}

// GetUserID returns the authenticated user ID.
func (c *CapturedData) GetUserID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userID
}

// SetUserEmail records the authenticated user's email address. Used by
// policy-aware middlewares to stamp identity onto upstream requests
// (e.g. x-litellm-end-user-id) without a management round-trip.
func (c *CapturedData) SetUserEmail(email string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userEmail = email
}

// GetUserEmail returns the authenticated user's email address. Returns
// the empty string when the auth path didn't carry an email (e.g.
// non-OIDC schemes or legacy JWTs minted before the email claim).
func (c *CapturedData) GetUserEmail() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userEmail
}

// SetUserGroups records the authenticated user's group memberships so
// downstream policy-aware middlewares can authorise the request without
// an additional management round-trip. The auth middleware populates this
// from ValidateSessionResponse / ValidateTunnelPeerResponse and from the
// session JWT's groups claim on cookie-bearing requests.
func (c *CapturedData) SetUserGroups(groups []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(groups) == 0 {
		c.userGroups = nil
		return
	}
	c.userGroups = append(c.userGroups[:0], groups...)
}

// GetUserGroups returns a copy of the authenticated user's group
// memberships.
func (c *CapturedData) GetUserGroups() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.userGroups) == 0 {
		return nil
	}
	out := make([]string, len(c.userGroups))
	copy(out, c.userGroups)
	return out
}

// SetUserGroupNames records the human-readable display names for the
// user's groups, ordered identically to UserGroups (positional
// pairing). Stamped onto upstream requests as X-NetBird-Groups so
// downstream services can read names rather than opaque ids.
func (c *CapturedData) SetUserGroupNames(names []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(names) == 0 {
		c.userGroupNames = nil
		return
	}
	c.userGroupNames = append(c.userGroupNames[:0], names...)
}

// GetUserGroupNames returns a copy of the authenticated user's group
// display names. Position i pairs with UserGroups[i]. May be shorter
// than UserGroups for tokens minted before names were resolvable; the
// consumer should fall back to ids for missing positions.
func (c *CapturedData) GetUserGroupNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.userGroupNames) == 0 {
		return nil
	}
	out := make([]string, len(c.userGroupNames))
	copy(out, c.userGroupNames)
	return out
}

// SetAuthMethod sets the authentication method used.
func (c *CapturedData) SetAuthMethod(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authMethod = method
}

// GetAuthMethod returns the authentication method used.
func (c *CapturedData) GetAuthMethod() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authMethod
}

// SetMetadata sets a key-value pair in the metadata map.
func (c *CapturedData) SetMetadata(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.metadata == nil {
		c.metadata = make(map[string]string)
	}
	c.metadata[key] = value
}

// GetMetadata returns a copy of the metadata map.
func (c *CapturedData) GetMetadata() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return maps.Clone(c.metadata)
}

// WithCapturedData adds a CapturedData struct to the context.
func WithCapturedData(ctx context.Context, data *CapturedData) context.Context {
	return context.WithValue(ctx, capturedDataKey, data)
}

// CapturedDataFromContext retrieves the CapturedData from context.
func CapturedDataFromContext(ctx context.Context) *CapturedData {
	v := ctx.Value(capturedDataKey)
	data, ok := v.(*CapturedData)
	if !ok {
		return nil
	}
	return data
}
