package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	rdpserver "github.com/netbirdio/netbird/client/rdp/server"
)

const (
	// DefaultTimeout is the default timeout for sideband auth requests.
	DefaultTimeout = 30 * time.Second

	// maxResponseSize is the maximum size of an auth response in bytes.
	maxResponseSize = 64 * 1024
)

// Client connects to a target peer's RDP sideband auth server to request access.
type Client struct {
	Timeout time.Duration
}

// New creates a new sideband RDP auth client.
func New() *Client {
	return &Client{
		Timeout: DefaultTimeout,
	}
}

// RequestAuth sends an authorization request to the target peer's sideband server
// and returns the response. The addr should be in "host:port" format.
func (c *Client) RequestAuth(ctx context.Context, addr string, req *rdpserver.AuthRequest) (*rdpserver.AuthResponse, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to RDP auth server at %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set connection deadline: %w", err)
		}
	}

	// Send request
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal auth request: %w", err)
	}

	if _, err := conn.Write(reqData); err != nil {
		return nil, fmt.Errorf("send auth request: %w", err)
	}

	// Signal we're done writing so the server can read the full request
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			return nil, fmt.Errorf("close write: %w", err)
		}
	}

	// Read response
	respData, err := io.ReadAll(io.LimitReader(conn, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}

	var resp rdpserver.AuthResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal auth response: %w", err)
	}

	return &resp, nil
}
