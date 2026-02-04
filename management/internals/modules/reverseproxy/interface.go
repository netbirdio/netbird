package reverseproxy

import (
	"context"
)

type Manager interface {
	GetAllReverseProxies(ctx context.Context, accountID, userID string) ([]*ReverseProxy, error)
	GetReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) (*ReverseProxy, error)
	CreateReverseProxy(ctx context.Context, accountID, userID string, reverseProxy *ReverseProxy) (*ReverseProxy, error)
	UpdateReverseProxy(ctx context.Context, accountID, userID string, reverseProxy *ReverseProxy) (*ReverseProxy, error)
	DeleteReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) error
	SetCertificateIssuedAt(ctx context.Context, accountID, reverseProxyID string) error
	SetStatus(ctx context.Context, accountID, reverseProxyID string, status ProxyStatus) error
}
