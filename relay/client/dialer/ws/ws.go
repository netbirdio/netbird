package ws

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func Dial(address string) (net.Conn, error) {
	wsURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	opts := &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(),
	}

	wsConn, resp, err := websocket.Dial(context.Background(), wsURL, opts)
	if err != nil {
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
