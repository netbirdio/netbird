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
	authMethod string
	metadata   map[string]string
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
