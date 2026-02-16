package proxy

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

type requestContextKey string

const (
	serviceIdKey    requestContextKey = "serviceId"
	accountIdKey    requestContextKey = "accountId"
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
	RequestID  string
	ServiceId  string
	AccountId  types.AccountID
	Origin     ResponseOrigin
	ClientIP   string
	UserID     string
	AuthMethod string
}

// GetRequestID safely gets the request ID
func (c *CapturedData) GetRequestID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RequestID
}

// SetServiceId safely sets the service ID
func (c *CapturedData) SetServiceId(serviceId string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ServiceId = serviceId
}

// GetServiceId safely gets the service ID
func (c *CapturedData) GetServiceId() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ServiceId
}

// SetAccountId safely sets the account ID
func (c *CapturedData) SetAccountId(accountId types.AccountID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AccountId = accountId
}

// GetAccountId safely gets the account ID
func (c *CapturedData) GetAccountId() types.AccountID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AccountId
}

// SetOrigin safely sets the response origin
func (c *CapturedData) SetOrigin(origin ResponseOrigin) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Origin = origin
}

// GetOrigin safely gets the response origin
func (c *CapturedData) GetOrigin() ResponseOrigin {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Origin
}

// SetClientIP safely sets the resolved client IP.
func (c *CapturedData) SetClientIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ClientIP = ip
}

// GetClientIP safely gets the resolved client IP.
func (c *CapturedData) GetClientIP() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ClientIP
}

// SetUserID safely sets the authenticated user ID.
func (c *CapturedData) SetUserID(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UserID = userID
}

// GetUserID safely gets the authenticated user ID.
func (c *CapturedData) GetUserID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UserID
}

// SetAuthMethod safely sets the authentication method used.
func (c *CapturedData) SetAuthMethod(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AuthMethod = method
}

// GetAuthMethod safely gets the authentication method used.
func (c *CapturedData) GetAuthMethod() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AuthMethod
}

// WithCapturedData adds a CapturedData struct to the context
func WithCapturedData(ctx context.Context, data *CapturedData) context.Context {
	return context.WithValue(ctx, capturedDataKey, data)
}

// CapturedDataFromContext retrieves the CapturedData from context
func CapturedDataFromContext(ctx context.Context) *CapturedData {
	v := ctx.Value(capturedDataKey)
	data, ok := v.(*CapturedData)
	if !ok {
		return nil
	}
	return data
}

func withServiceId(ctx context.Context, serviceId string) context.Context {
	return context.WithValue(ctx, serviceIdKey, serviceId)
}

func ServiceIdFromContext(ctx context.Context) string {
	v := ctx.Value(serviceIdKey)
	serviceId, ok := v.(string)
	if !ok {
		return ""
	}
	return serviceId
}
func withAccountId(ctx context.Context, accountId types.AccountID) context.Context {
	return context.WithValue(ctx, accountIdKey, accountId)
}

func AccountIdFromContext(ctx context.Context) types.AccountID {
	v := ctx.Value(accountIdKey)
	accountId, ok := v.(types.AccountID)
	if !ok {
		return ""
	}
	return accountId
}
