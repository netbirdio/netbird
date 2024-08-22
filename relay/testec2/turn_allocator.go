//go:build linux || darwin

package main

import (
	"fmt"
	"net"

	"github.com/pion/logging"
	"github.com/pion/turn/v3"
	log "github.com/sirupsen/logrus"
)

type TurnConn struct {
	conn       net.Conn
	turnClient *turn.Client
	relayConn  net.PacketConn
}

func (tc *TurnConn) Address() net.Addr {
	return tc.relayConn.LocalAddr()
}

func (tc *TurnConn) Close() {
	_ = tc.relayConn.Close()
	tc.turnClient.Close()
	_ = tc.conn.Close()
}

func AllocateTurnClient(serverAddr string) *TurnConn {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	turnClient, err := getTurnClient(serverAddr, conn)
	if err != nil {
		log.Fatal(err)
	}

	relayConn, err := turnClient.Allocate()
	if err != nil {
		log.Fatal(err)
	}

	return &TurnConn{
		conn:       conn,
		turnClient: turnClient,
		relayConn:  relayConn,
	}
}

func getTurnClient(address string, conn net.Conn) (*turn.Client, error) {
	// Dial TURN Server
	addrStr := fmt.Sprintf("%s:%d", address, 443)

	fac := logging.NewDefaultLoggerFactory()
	//fac.DefaultLogLevel = logging.LogLevelTrace

	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg := &turn.ClientConfig{
		TURNServerAddr: address,
		Conn:           turn.NewSTUNConn(conn),
		Username:       "test",
		Password:       "test",
		LoggerFactory:  fac,
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TURN client for server %s: %s", addrStr, err)
	}

	// Start listening on the conn provided.
	err = client.Listen()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to listen on TURN client for server %s: %s", addrStr, err)
	}

	return client, nil
}
