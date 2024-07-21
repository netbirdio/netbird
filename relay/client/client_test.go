package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/auth/hmac"
	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/relay/server"
)

var (
	av               = &auth.AllowAllAuth{}
	hmacTokenStore   = &hmac.TokenStore{}
	serverListenAddr = "127.0.0.1:1234"
	serverURL        = "rel://127.0.0.1:1234"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("error", "console")
	code := m.Run()
	os.Exit(code)
}

func TestClient(t *testing.T) {
	ctx := context.Background()

	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		listenCfg := server.ListenerConfig{Address: serverListenAddr}
		err := srv.Listen(listenCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for server to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}
	t.Log("alice connecting to server")
	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientAlice.Close()

	t.Log("placeholder connecting to server")
	clientPlaceHolder := NewClient(ctx, serverURL, hmacTokenStore, "clientPlaceHolder")
	err = clientPlaceHolder.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientPlaceHolder.Close()

	t.Log("Bob connecting to server")
	clientBob := NewClient(ctx, serverURL, hmacTokenStore, "bob")
	err = clientBob.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientBob.Close()

	t.Log("Alice open connection to Bob")
	connAliceToBob, err := clientAlice.OpenConn("bob")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	t.Log("Bob open connection to Alice")
	connBobToAlice, err := clientBob.OpenConn("alice")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	payload := "hello bob, I am alice"
	_, err = connAliceToBob.Write([]byte(payload))
	if err != nil {
		t.Fatalf("failed to write to channel: %s", err)
	}
	log.Debugf("alice sent message to bob")

	buf := make([]byte, 65535)
	n, err := connBobToAlice.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from channel: %s", err)
	}
	log.Debugf("on new message from alice to bob")

	if payload != string(buf[:n]) {
		t.Fatalf("expected %s, got %s", payload, string(buf[:n]))
	}
}

func TestDataTransfer(t *testing.T) {
	dataSize := 1024 * 1024 * 10

	testData, err := seedRandomData(dataSize)
	if err != nil {
		t.Fatalf("failed to seed random data: %s", err)
	}

	for _, peerPairs := range []int{1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100} {
		t.Run(fmt.Sprintf("peerPairs-%d", peerPairs), func(t *testing.T) {
			transfer(t, testData, peerPairs)
		})
	}
}

func transfer(t *testing.T, testData []byte, peerPairs int) {
	t.Helper()
	ctx := context.Background()
	port := 35000 + peerPairs
	serverAddress := fmt.Sprintf("127.0.0.1:%d", port)
	serverConnURL := fmt.Sprintf("rel://%s", serverAddress)

	srv := server.NewServer(serverConnURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		listenCfg := server.ListenerConfig{Address: serverAddress}
		err := srv.Listen(listenCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for server to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientsSender := make([]*Client, peerPairs)
	for i := 0; i < cap(clientsSender); i++ {
		c := NewClient(ctx, serverConnURL, hmacTokenStore, "sender-"+fmt.Sprint(i))
		err := c.Connect()
		if err != nil {
			t.Fatalf("failed to connect to server: %s", err)
		}
		clientsSender[i] = c
	}

	clientsReceiver := make([]*Client, peerPairs)
	for i := 0; i < cap(clientsReceiver); i++ {
		c := NewClient(ctx, serverConnURL, hmacTokenStore, "receiver-"+fmt.Sprint(i))
		err := c.Connect()
		if err != nil {
			t.Fatalf("failed to connect to server: %s", err)
		}
		clientsReceiver[i] = c
	}

	connsSender := make([]net.Conn, 0, peerPairs)
	connsReceiver := make([]net.Conn, 0, peerPairs)
	for i := 0; i < len(clientsSender); i++ {
		conn, err := clientsSender[i].OpenConn("receiver-" + fmt.Sprint(i))
		if err != nil {
			t.Fatalf("failed to bind channel: %s", err)
		}
		connsSender = append(connsSender, conn)

		conn, err = clientsReceiver[i].OpenConn("sender-" + fmt.Sprint(i))
		if err != nil {
			t.Fatalf("failed to bind channel: %s", err)
		}
		connsReceiver = append(connsReceiver, conn)
	}

	var transferDuration []time.Duration
	wg := sync.WaitGroup{}
	for i := 0; i < len(connsSender); i++ {
		wg.Add(2)
		start := time.Now()
		go func(i int) {
			pieceSize := 1024
			testDataLen := len(testData)

			for j := 0; j < testDataLen; j += pieceSize {
				end := j + pieceSize
				if end > testDataLen {
					end = testDataLen
				}
				_, err := connsSender[i].Write(testData[j:end])
				if err != nil {
					t.Fatalf("failed to write to channel: %s", err)
				}
			}
			wg.Done()
		}(i)

		go func(i int, start time.Time) {
			buf := make([]byte, 8192)
			rcv := 0
			for receivedSize := 0; receivedSize < len(testData); {

				n, err := connsReceiver[i].Read(buf)
				if err != nil {
					t.Fatalf("failed to read from channel: %s", err)
				}

				receivedSize += n
				rcv += n
			}
			transferDuration = append(transferDuration, time.Since(start))
			wg.Done()
		}(i, start)
	}

	wg.Wait()

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

func TestRegistration(t *testing.T) {
	ctx := context.Background()
	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	// wait for server to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err := clientAlice.Connect()
	if err != nil {
		_ = srv.Close()
		t.Fatalf("failed to connect to server: %s", err)
	}
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close conn: %s", err)
	}
	err = srv.Close()
	if err != nil {
		t.Errorf("failed to close server: %s", err)
	}
}

func TestRegistrationTimeout(t *testing.T) {
	ctx := context.Background()
	fakeUDPListener, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 1234,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		t.Fatalf("failed to bind UDP server: %s", err)
	}
	defer func(fakeUDPListener *net.UDPConn) {
		_ = fakeUDPListener.Close()
	}(fakeUDPListener)

	fakeTCPListener, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: 1234,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		t.Fatalf("failed to bind TCP server: %s", err)
	}
	defer func(fakeTCPListener *net.TCPListener) {
		_ = fakeTCPListener.Close()
	}(fakeTCPListener)

	clientAlice := NewClient(ctx, "127.0.0.1:1234", hmacTokenStore, "alice")
	err = clientAlice.Connect()
	if err == nil {
		t.Errorf("failed to connect to server: %s", err)
	}
	log.Debugf("%s", err)
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close conn: %s", err)
	}
}

func TestEcho(t *testing.T) {
	ctx := context.Background()
	idAlice := "alice"
	idBob := "bob"
	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, idAlice)
	err := clientAlice.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err := clientAlice.Close()
		if err != nil {
			t.Errorf("failed to close Alice client: %s", err)
		}
	}()

	clientBob := NewClient(ctx, serverURL, hmacTokenStore, idBob)
	err = clientBob.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err := clientBob.Close()
		if err != nil {
			t.Errorf("failed to close Bob client: %s", err)
		}
	}()

	connAliceToBob, err := clientAlice.OpenConn(idBob)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	connBobToAlice, err := clientBob.OpenConn(idAlice)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	payload := "hello bob, I am alice"
	_, err = connAliceToBob.Write([]byte(payload))
	if err != nil {
		t.Fatalf("failed to write to channel: %s", err)
	}

	buf := make([]byte, 65535)
	n, err := connBobToAlice.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from channel: %s", err)
	}

	_, err = connBobToAlice.Write(buf[:n])
	if err != nil {
		t.Fatalf("failed to write to channel: %s", err)
	}

	n, err = connAliceToBob.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from channel: %s", err)
	}

	if payload != string(buf[:n]) {
		t.Fatalf("expected %s, got %s", payload, string(buf[:n]))
	}
}

func TestBindToUnavailabePeer(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}
	_, err = clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	log.Infof("closing client")
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}
}

func TestBindReconnect(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	_, err = clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	clientBob := NewClient(ctx, serverURL, hmacTokenStore, "bob")
	err = clientBob.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	chBob, err := clientBob.OpenConn("alice")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	log.Infof("closing client Alice")
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}

	clientAlice = NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err = clientAlice.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	chAlice, err := clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	testString := "hello alice, I am bob"
	_, err = chBob.Write([]byte(testString))
	if err != nil {
		t.Errorf("failed to write to channel: %s", err)
	}

	buf := make([]byte, 65535)
	n, err := chAlice.Read(buf)
	if err != nil {
		t.Errorf("failed to read from channel: %s", err)
	}

	if testString != string(buf[:n]) {
		t.Errorf("expected %s, got %s", testString, string(buf[:n]))
	}

	log.Infof("closing client")
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}
}

func TestCloseConn(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	conn, err := clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	log.Infof("closing connection")
	err = conn.Close()
	if err != nil {
		t.Errorf("failed to close connection: %s", err)
	}

	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Errorf("unexpected reading from closed connection")
	}

	_, err = conn.Write([]byte("hello"))
	if err == nil {
		t.Errorf("unexpected writing from closed connection")
	}
}

func TestCloseRelayConn(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			log.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(ctx, serverURL, hmacTokenStore, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}

	conn, err := clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	_ = clientAlice.relayConn.Close()

	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Errorf("unexpected reading from closed connection")
	}

	_, err = clientAlice.OpenConn("bob")
	if err == nil {
		t.Errorf("unexpected opening connection to closed server")
	}
}

func TestCloseByServer(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv1 := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)

	go func() {
		err := srv1.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	idAlice := "alice"
	log.Debugf("connect by alice")
	relayClient := NewClient(ctx, serverURL, hmacTokenStore, idAlice)
	err := relayClient.Connect()
	if err != nil {
		log.Fatalf("failed to connect to server: %s", err)
	}

	disconnected := make(chan struct{})
	relayClient.SetOnDisconnectListener(func() {
		log.Infof("client disconnected")
		close(disconnected)
	})

	err = srv1.Close()
	if err != nil {
		t.Fatalf("failed to close server: %s", err)
	}

	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		log.Fatalf("timeout waiting for client to disconnect")
	}

	_, err = relayClient.OpenConn("bob")
	if err == nil {
		t.Errorf("unexpected opening connection to closed server")
	}
}

func TestCloseByClient(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv := server.NewServer(serverURL, false, av)
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	idAlice := "alice"
	log.Debugf("connect by alice")
	relayClient := NewClient(ctx, serverURL, hmacTokenStore, idAlice)
	err := relayClient.Connect()
	if err != nil {
		log.Fatalf("failed to connect to server: %s", err)
	}

	err = relayClient.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}

	_, err = relayClient.OpenConn("bob")
	if err == nil {
		t.Errorf("unexpected opening connection to closed server")
	}

	err = srv.Close()
	if err != nil {
		t.Fatalf("failed to close server: %s", err)
	}
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

func seedRandomData(size int) ([]byte, error) {
	token := make([]byte, size)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	return token, nil
}
