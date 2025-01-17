package ws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"

	"github.com/netbirdio/netbird/relay/server/listener/ws"
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

	opts := &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(),
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

func httpClientNbDialer() *http.Client {
	customDialer := nbnet.NewDialer()

	customTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return customDialer.DialContext(ctx, network, addr)
		},
	}

	return &http.Client{
		Transport: customTransport,
	}
}
