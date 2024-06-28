package ws

import (
	"context"
	"fmt"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func Dial(address string) (net.Conn, error) {

	hostName, _, err := net.SplitHostPort(address)

	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		log.Errorf("failed to resolve address of Relay server: %s", address)
		return nil, err
	}

	url := fmt.Sprintf("ws://%s:%d", addr.IP.String(), addr.Port)
	opts := &websocket.DialOptions{
		Host:       hostName,
		HTTPClient: httpClientNbDialer(),
	}

	wsConn, _, err := websocket.Dial(context.Background(), url, opts)
	if err != nil {
		log.Errorf("failed to dial to Relay server '%s': %s", url, err)
		return nil, err
	}

	conn := NewConn(wsConn, addr)

	return conn, nil
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
