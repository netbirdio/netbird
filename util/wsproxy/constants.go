package wsproxy

import "errors"

// ProxyPath is the standard path where the WebSocket proxy is mounted on servers.
const ProxyPath = "/ws-proxy"

// Common errors
var (
	ErrConnectionTimeout  = errors.New("WebSocket connection timeout")
	ErrConnectionFailed   = errors.New("WebSocket connection failed")
	ErrBackendUnavailable = errors.New("backend unavailable")
)
