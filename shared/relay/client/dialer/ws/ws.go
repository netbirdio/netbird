package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/util"
)

type Dialer struct {
}

func (d Dialer) Protocol() string {
	return Network
}

func (d Dialer) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	wsURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	host, err := requestHost(wsURL, serverName)
	if err != nil {
		return nil, err
	}

	var underlying net.Conn
	opts := createDialOptions(serverName, host, &underlying)

	wsConn, resp, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		// websocket.Dial wraps the cause in verbose layers; surface the
		// underlying network error when present.
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return nil, opErr
		}
		return nil, err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	conn := NewConn(wsConn, address, underlying)
	return conn, nil
}

// prepareURL rewrites a rel://host[:port] or rels://host[:port] address into a
// ws://host[:port]/relay or wss://host[:port]/relay URL, preserving any
// non-standard port from the input.
func prepareURL(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("parse relay address %q: %w", address, err)
	}
	switch parsed.Scheme {
	case "rel":
		parsed.Scheme = "ws"
	case "rels":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("missing host in relay address %q", address)
	}
	parsed.Path = relay.WebSocketURLPath
	return parsed.String(), nil
}

// requestHost keeps the server name in the Host header when dialing by IP, so
// proxies that route by host still match.
func requestHost(wsURL, serverName string) (string, error) {
	if serverName == "" {
		return "", nil
	}
	parsed, err := url.Parse(wsURL)
	if err != nil {
		return "", fmt.Errorf("parse relay URL %q: %w", wsURL, err)
	}
	if port := parsed.Port(); port != "" {
		return net.JoinHostPort(serverName, port), nil
	}
	return serverName, nil
}

// httpClientNbDialer builds the http client used by the websocket library.
// underlyingOut, when non-nil, is populated with the raw conn from the
// transport's DialContext so the caller can read its RemoteAddr.
func httpClientNbDialer(serverName string, underlyingOut *net.Conn) *http.Client {
	customDialer := nbnet.NewDialer()

	customTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := customDialer.DialContext(ctx, network, addr)
			if err == nil && underlyingOut != nil {
				*underlyingOut = c
			}
			return c, err
		},
		TLSClientConfig: &tls.Config{
			RootCAs:    util.GetGlobalCertPool(),
			ServerName: serverName,
		},
	}

	return &http.Client{
		Transport: customTransport,
	}
}
