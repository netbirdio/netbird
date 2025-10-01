package wsproxy

import "errors"

// ProxyPath is the base path where the WebSocket proxy is mounted on servers.
const ProxyPath = "/ws-proxy"

// Component paths that are appended to ProxyPath
const (
	ManagementComponent = "/management"
	SignalComponent     = "/signal"
	FlowComponent       = "/flow"
)

// Common errors
var (
	ErrConnectionTimeout  = errors.New("WebSocket connection timeout")
	ErrConnectionFailed   = errors.New("WebSocket connection failed")
	ErrBackendUnavailable = errors.New("backend unavailable")
)
