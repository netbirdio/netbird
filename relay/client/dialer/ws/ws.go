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

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"

	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/util/embeddedroots"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type Dialer struct {
}

func (d Dialer) Protocol() string {
	return "WS"
}

func (d Dialer) Dial(ctx context.Context, address string) (net.Conn, error) {
	wsURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	httpClient, err := httpClientNbDialer()
	if err != nil {
		return nil, err
	}
	opts := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	parsedURL.Path = ws.URLPath

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

	conn := NewConn(wsConn, address)
	return conn, nil
}

func prepareURL(address string) (string, error) {
	if !strings.HasPrefix(address, "rel:") && !strings.HasPrefix(address, "rels:") {
		return "", fmt.Errorf("unsupported scheme: %s", address)
	}

	return strings.Replace(address, "rel", "ws", 1), nil
}

func httpClientNbDialer() (*http.Client, error) {
	customDialer := nbnet.NewDialer()

	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		log.Debug("System cert pool not available; falling back to embedded cert.")
		certPool = embeddedroots.Get()
	}

	customTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return customDialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}

	return &http.Client{
		Transport: customTransport,
	}, nil
}
