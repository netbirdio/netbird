package ws

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"

	"github.com/netbirdio/netbird/relay/server/listener/ws"
	nbnet "github.com/netbirdio/netbird/util/net"
)

func Dial(address string) (net.Conn, time.Duration, error) {
	wsURL, err := prepareURL(address)
	if err != nil {
		return nil, 0, err
	}

	opts := &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(),
	}

	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		return nil, 0, err
	}
	parsedURL.Path = ws.URLPath

	var connStart, firstByte time.Time
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		ConnectStart:         func(network, addr string) { connStart = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	})
	wsConn, resp, err := websocket.Dial(ctx, parsedURL.String(), opts)
	if err != nil {
		log.Errorf("failed to dial to Relay server '%s': %s", wsURL, err)
		return nil, 0, err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	conn := NewConn(wsConn, address)
	return conn, firstByte.Sub(connStart), nil
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
