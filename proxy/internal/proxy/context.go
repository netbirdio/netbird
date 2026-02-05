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

// CapturedData is a mutable struct that allows downstream handlers
// to pass data back up the middleware chain.
type CapturedData struct {
	mu        sync.RWMutex
	RequestID string
	ServiceId string
	AccountId types.AccountID
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
