package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/util/embeddedroots"
)

type Dialer struct {
}

func (d Dialer) Protocol() string {
	return "WS"
}

func (d Dialer) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	wsURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	var underlying net.Conn
	opts := createDialOptions(serverName, &underlying)

	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	parsedURL.Path = relay.WebSocketURLPath

	wsConn, resp, err := websocket.Dial(ctx, parsedURL.String(), opts)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		log.Errorf("failed to dial to Relay server '%s': %s", wsURL, err)
		return nil, err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	conn := NewConn(wsConn, address, underlying)
	return conn, nil
}

func prepareURL(address string) (string, error) {
	if !strings.HasPrefix(address, "rel:") && !strings.HasPrefix(address, "rels:") {
		return "", fmt.Errorf("unsupported scheme: %s", address)
	}

	return strings.Replace(address, "rel", "ws", 1), nil
}

// httpClientNbDialer builds the http client used by the websocket library.
// underlyingOut, when non-nil, is populated with the raw conn from the
// transport's DialContext so the caller can read its RemoteAddr.
func httpClientNbDialer(serverName string, underlyingOut *net.Conn) *http.Client {
	customDialer := nbnet.NewDialer()

	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
		certPool = embeddedroots.Get()
	}

	customTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := customDialer.DialContext(ctx, network, addr)
			if err == nil && underlyingOut != nil {
				*underlyingOut = c
			}
			return c, err
		},
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			ServerName: serverName,
		},
	}

	return &http.Client{
		Transport: customTransport,
	}
}
