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

	wsConn, _, err := websocket.Dial(context.Background(), wsURL, opts)
	if err != nil {
		log.Errorf("failed to dial to Relay server '%s': %s", wsURL, err)
		return nil, err
	}

	/*
		response.Body.(net.Conn).LocalAddr()
		unc, ok := response.Body.(net.Conn)
		if !ok {
			log.Errorf("failed to get local address: %s", err)
			return nil, fmt.Errorf("failed to get local address")
		}

	*/
	// todo figure out the proper address
	dummy := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}

	conn := NewConn(wsConn, dummy, dummy)
	return conn, nil
}

func prepareURL(address string) (string, error) {
	if !strings.HasPrefix(address, "rel") {
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
