//go:build e2e

package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// AdminEmail and AdminPassword are the owner Bootstrap creates. A suite that drives a
// browser login at the embedded IdP signs in with them.
const (
	AdminEmail    = "admin@netbird.test"
	AdminPassword = "Netbird-e2e-Passw0rd!" //nolint:gosec // static throwaway test credential
)

// PublicURL is the scheme and host the deployment believes it is served at: the embedded
// IdP issuer without its /oauth2 path. Login flows hand out URLs on it, and the host
// cannot reach it directly, so requests to it go through Browser.
func (c *Combined) PublicURL() string {
	return strings.TrimSuffix(containerIssuer, "/oauth2")
}

// Browser returns an HTTP client that behaves like a user's browser for login flows: it
// keeps cookies, and it reaches PublicURL by dialing the container's mapped port instead,
// so redirects between the embedded IdP and management resolve as they would for a user.
// Every other address is dialed as given. Restart can move the mapped port, so take a new
// Browser after one.
func (c *Combined) Browser() (*http.Client, error) {
	public, err := url.Parse(c.PublicURL())
	if err != nil {
		return nil, fmt.Errorf("parse public URL: %w", err)
	}
	mapped, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if mapped.Host == "" {
		return nil, fmt.Errorf("base URL %q names no host", c.BaseURL)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	publicAddr := hostPort(public)
	mappedAddr := hostPort(mapped)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == publicAddr {
				addr = mappedAddr
			}
			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{Jar: jar, Transport: transport, Timeout: 60 * time.Second}, nil
}

// hostPort is the address the transport dials for u: its host with the scheme's default
// port filled in when the URL names none.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
