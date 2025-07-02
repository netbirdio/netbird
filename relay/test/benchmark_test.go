package test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/relay/auth/allow"
	"github.com/netbirdio/netbird/relay/auth/hmac"
	"github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/util"
	"github.com/pion/logging"
	"github.com/pion/turn/v3"
)

var (
	av             = &allow.Auth{}
	hmacTokenStore = &hmac.TokenStore{}
	pairs          = []int{1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	dataSize       = 1024 * 1024 * 10
)

func TestMain(m *testing.M) {
	_ = util.InitLog("error", "console")
	code := m.Run()
	os.Exit(code)
}

func TestRelayDataTransfer(t *testing.T) {
	t.SkipNow() // skip this test on CI because it is a benchmark test
	testData, err := seedRandomData(dataSize)
	if err != nil {
		t.Fatalf("failed to seed random data: %s", err)
	}

	for _, peerPairs := range pairs {
		t.Run(fmt.Sprintf("peerPairs-%d", peerPairs), func(t *testing.T) {
			transfer(t, testData, peerPairs)
		})
	}
}

// TestTurnDataTransfer run turn server:
// docker run --rm --name coturn -d --network=host coturn/coturn --user test:test
func TestTurnDataTransfer(t *testing.T) {
	t.SkipNow() // skip this test on CI because it is a benchmark test
	testData, err := seedRandomData(dataSize)
	if err != nil {
		t.Fatalf("failed to seed random data: %s", err)
	}

	for _, peerPairs := range pairs {
		t.Run(fmt.Sprintf("peerPairs-%d", peerPairs), func(t *testing.T) {
			runTurnTest(t, testData, peerPairs)
		})
	}
}

func transfer(t *testing.T, testData []byte, peerPairs int) {
	t.Helper()
	ctx := context.Background()
	port := 35000 + peerPairs
	serverAddress := fmt.Sprintf("127.0.0.1:%d", port)
	serverConnURL := fmt.Sprintf("rel://%s", serverAddress)
	serverCfg := server.Config{
		ExposedAddress: serverConnURL,
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		listenCfg := server.ListenerConfig{Address: serverAddress}
		err := srv.Listen(listenCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for server to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientsSender := make([]*client.Client, peerPairs)
	for i := 0; i < cap(clientsSender); i++ {
		c := client.NewClient(ctx, serverConnURL, hmacTokenStore, "sender-"+fmt.Sprint(i))
		err := c.Connect()
		if err != nil {
			t.Fatalf("failed to connect to server: %s", err)
		}
		clientsSender[i] = c
	}

	clientsReceiver := make([]*client.Client, peerPairs)
	for i := 0; i < cap(clientsReceiver); i++ {
		c := client.NewClient(ctx, serverConnURL, hmacTokenStore, "receiver-"+fmt.Sprint(i))
		err := c.Connect()
		if err != nil {
			t.Fatalf("failed to connect to server: %s", err)
		}
		clientsReceiver[i] = c
	}

	connsSender := make([]net.Conn, 0, peerPairs)
	connsReceiver := make([]net.Conn, 0, peerPairs)
	for i := 0; i < len(clientsSender); i++ {
		conn, err := clientsSender[i].OpenConn(ctx, "receiver-"+fmt.Sprint(i))
		if err != nil {
			t.Fatalf("failed to bind channel: %s", err)
		}
		connsSender = append(connsSender, conn)

		conn, err = clientsReceiver[i].OpenConn(ctx, "sender-"+fmt.Sprint(i))
		if err != nil {
			t.Fatalf("failed to bind channel: %s", err)
		}
		connsReceiver = append(connsReceiver, conn)
	}

	var transferDuration []time.Duration
	wg := sync.WaitGroup{}
	var writeErr error
	var readErr error
	for i := 0; i < len(connsSender); i++ {
		wg.Add(2)
		start := time.Now()
		go func(i int) {
			defer wg.Done()
			pieceSize := 1024
			testDataLen := len(testData)

			for j := 0; j < testDataLen; j += pieceSize {
				end := j + pieceSize
				if end > testDataLen {
					end = testDataLen
				}
				_, writeErr = connsSender[i].Write(testData[j:end])
				if writeErr != nil {
					return
				}
			}

		}(i)

		go func(i int, start time.Time) {
			defer wg.Done()
			buf := make([]byte, 8192)
			rcv := 0
			var n int
			for receivedSize := 0; receivedSize < len(testData); {

				n, readErr = connsReceiver[i].Read(buf)
				if readErr != nil {
					return
				}

				receivedSize += n
				rcv += n
			}
			transferDuration = append(transferDuration, time.Since(start))
		}(i, start)
	}

	wg.Wait()

	if writeErr != nil {
		t.Fatalf("failed to write to channel: %s", err)
	}

	if readErr != nil {
		t.Fatalf("failed to read from channel: %s", err)
	}

	// calculate the megabytes per second from the average transferDuration against the dataSize
	var totalDuration time.Duration
	for _, d := range transferDuration {
		totalDuration += d
	}
	avgDuration := totalDuration / time.Duration(len(transferDuration))
	mbps := float64(len(testData)) / avgDuration.Seconds() / 1024 / 1024
	t.Logf("average transfer duration: %s", avgDuration)
	t.Logf("average transfer speed: %.2f MB/s", mbps)

	for i := 0; i < len(connsSender); i++ {
		err := connsSender[i].Close()
		if err != nil {
			t.Errorf("failed to close connection: %s", err)
		}

		err = connsReceiver[i].Close()
		if err != nil {
			t.Errorf("failed to close connection: %s", err)
		}
	}
}

func runTurnTest(t *testing.T, testData []byte, maxPairs int) {
	t.Helper()
	var transferDuration []time.Duration
	var wg sync.WaitGroup

	for i := 0; i < maxPairs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := runTurnDataTransfer(t, testData)
			transferDuration = append(transferDuration, d)
		}()

	}
	wg.Wait()

	var totalDuration time.Duration
	for _, d := range transferDuration {
		totalDuration += d
	}
	avgDuration := totalDuration / time.Duration(len(transferDuration))
	mbps := float64(len(testData)) / avgDuration.Seconds() / 1024 / 1024
	t.Logf("average transfer duration: %s", avgDuration)
	t.Logf("average transfer speed: %.2f MB/s", mbps)
}

func runTurnDataTransfer(t *testing.T, testData []byte) time.Duration {
	t.Helper()
	testDataLen := len(testData)
	relayAddress := "192.168.0.10:3478"
	conn, err := net.Dial("tcp", relayAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	turnClient, err := getTurnClient(t, relayAddress, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer turnClient.Close()

	relayConn, err := turnClient.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer func(relayConn net.PacketConn) {
		_ = relayConn.Close()
	}(relayConn)

	receiverConn, err := net.Dial("udp", relayConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func(receiverConn net.Conn) {
		_ = receiverConn.Close()
	}(receiverConn)

	var (
		tb        int
		start     time.Time
		timerInit bool
		readDone  = make(chan struct{})
		ack       = make([]byte, 1)
	)
	go func() {
		defer func() {
			readDone <- struct{}{}
		}()
		buff := make([]byte, 8192)
		for {
			n, e := receiverConn.Read(buff)
			if e != nil {
				return
			}
			if !timerInit {
				start = time.Now()
				timerInit = true
			}
			tb += n
			_, _ = receiverConn.Write(ack)

			if tb >= testDataLen {
				return
			}
		}
	}()

	pieceSize := 1024
	ackBuff := make([]byte, 1)
	pipelineSize := 10
	for j := 0; j < testDataLen; j += pieceSize {
		end := j + pieceSize
		if end > testDataLen {
			end = testDataLen
		}
		_, err := relayConn.WriteTo(testData[j:end], receiverConn.LocalAddr())
		if err != nil {
			t.Fatalf("failed to write to channel: %s", err)
		}
		if pipelineSize == 0 {
			_, _, _ = relayConn.ReadFrom(ackBuff)
		} else {
			pipelineSize--
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	select {
	case <-readDone:
		if tb != testDataLen {
			t.Fatalf("failed to read all data: %d/%d", tb, testDataLen)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	return time.Since(start)
}

func getTurnClient(t *testing.T, address string, conn net.Conn) (*turn.Client, error) {
	t.Helper()
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

func seedRandomData(size int) ([]byte, error) {
	token := make([]byte, size)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func waitForServerToStart(errChan chan error) error {
	select {
	case err := <-errChan:
		if err != nil {
			return err
		}
	case <-time.After(300 * time.Millisecond):
		return nil
	}
	return nil
}
