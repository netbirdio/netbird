package main

import (
	"fmt"
	"net"
	"time"

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

func (tc *TurnConn) WriteTestData(testData []byte, dstAddr net.Addr) {
	log.Infof("write test data to: %s", dstAddr)
	testDataSize := len(testData)
	si := NewStartInidication(time.Now(), testDataSize)
	_, err := tc.relayConn.WriteTo(si, dstAddr)
	if err != nil {
		log.Errorf("failed to write to: %s, %s", dstAddr, err)
		return
	}

	pieceSize := 1024
	ackBuff := make([]byte, 1)
	pipelineSize := 10
	for j := 0; j < testDataSize; j += pieceSize {
		end := j + pieceSize
		if end > testDataSize {
			end = testDataSize
		}
		_, err := tc.relayConn.WriteTo(testData[j:end], dstAddr)
		if err != nil {
			log.Fatalf("failed to write to channel: %s", err)
		}
		if pipelineSize == 0 {
			_, _, _ = tc.relayConn.ReadFrom(ackBuff)
		} else {
			pipelineSize--
		}
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

type UDPConn struct {
	net.Conn
}

func Dial(addr string) (*UDPConn, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return &UDPConn{conn}, nil
}

func (c UDPConn) ReadTestData(c2 *UDPConn) time.Duration {
	log.Infof("reading test data from TURN relay")
	var (
		tb  int
		ack = make([]byte, 1)
	)
	buff := make([]byte, 8192)
	n, err := c.Conn.Read(buff)
	if err != nil {
		log.Errorf("failed to read from channel: %s", err)
		return 0
	}

	si := DecodeStartIndication(buff[:n])
	log.Infof("received start indication: %v", si)

	for {
		n, e := c.Conn.Read(buff)
		if e != nil {
			return 0
		}
		tb += n
		_, _ = c.Conn.Write(ack)

		if tb >= si.TransferSize {
			break
		}
	}

	return time.Since(si.Started)
}
