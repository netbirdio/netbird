package client

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/relay/server"
)

var (
	hmacTokenStore = &hmac.TokenStore{}
)

func TestMain(m *testing.M) {
	_ = util.InitLog("debug", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

// newClientTestServerConfig creates a new server config for client testing with the given address
func newClientTestServerConfig(address string) server.Config {
	return server.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: "rel://" + address,
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	}
}

func TestClient(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:50001"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		listenCfg := server.ListenerConfig{Address: serverListenAddr}
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
	t.Log("alice connecting to server")
	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientAlice.Close()

	t.Log("placeholder connecting to server")
	clientPlaceHolder := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "clientPlaceHolder", iface.DefaultMTU)
	err = clientPlaceHolder.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientPlaceHolder.Close()

	t.Log("Bob connecting to server")
	clientBob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	err = clientBob.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientBob.Close()

	t.Log("Alice open connection to Bob")
	connAliceToBob, err := clientAlice.OpenConn(ctx, "bob")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	t.Log("Bob open connection to Alice")
	connBobToAlice, err := clientBob.OpenConn(ctx, "alice")
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

func TestRegistration(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:50101"
	serverCfg := newClientTestServerConfig(serverListenAddr)
	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
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

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		_ = srv.Shutdown(ctx)
		t.Fatalf("failed to connect to server: %s", err)
	}
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close conn: %s", err)
	}
	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("failed to close server: %s", err)
	}
}

func TestRegistrationTimeout(t *testing.T) {
	ctx := context.Background()
	fakeUDPListener, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 50201,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		t.Fatalf("failed to bind UDP server: %s", err)
	}
	defer func(fakeUDPListener *net.UDPConn) {
		_ = fakeUDPListener.Close()
	}(fakeUDPListener)

	fakeTCPListener, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: 50201,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		t.Fatalf("failed to bind TCP server: %s", err)
	}
	defer func(fakeTCPListener *net.TCPListener) {
		_ = fakeTCPListener.Close()
	}(fakeTCPListener)

	clientAlice := NewClient("127.0.0.1:50201", hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
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
	serverListenAddr := "127.0.0.1:50301"
	serverCfg := newClientTestServerConfig(serverListenAddr)
	idAlice := "alice"
	idBob := "bob"
	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
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

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, idAlice, iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err := clientAlice.Close()
		if err != nil {
			t.Errorf("failed to close Alice client: %s", err)
		}
	}()

	clientBob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, idBob, iface.DefaultMTU)
	err = clientBob.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err := clientBob.Close()
		if err != nil {
			t.Errorf("failed to close Bob client: %s", err)
		}
	}()

	connAliceToBob, err := clientAlice.OpenConn(ctx, idBob)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	connBobToAlice, err := clientBob.OpenConn(ctx, idAlice)
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
	serverListenAddr := "127.0.0.1:50401"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}
	_, err = clientAlice.OpenConn(ctx, "bob")
	if err == nil {
		t.Errorf("expected error when binding to unavailable peer, got nil")
	}

	log.Infof("closing client")
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}
}

func TestBindReconnect(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:50501"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}

	clientBob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	err = clientBob.Connect(ctx)
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	_, err = clientAlice.OpenConn(ctx, "bob")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	chBob, err := clientBob.OpenConn(ctx, "alice")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	log.Infof("closing client Alice")
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}

	clientAlice = NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	chAlice, err := clientAlice.OpenConn(ctx, "bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	testString := "hello alice, I am bob"
	_, err = chBob.Write([]byte(testString))
	if err == nil {
		t.Errorf("expected error when writing to channel, got nil")
	}

	chBob, err = clientBob.OpenConn(ctx, "alice")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

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
	serverListenAddr := "127.0.0.1:50601"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	bob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	err = bob.Connect(ctx)
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	conn, err := clientAlice.OpenConn(ctx, "bob")
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
	serverListenAddr := "127.0.0.1:50701"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Shutdown(ctx)
		if err != nil {
			log.Errorf("failed to close server: %s", err)
		}
	}()

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	bob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	err = bob.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}

	conn, err := clientAlice.OpenConn(ctx, "bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	_ = clientAlice.relayConn.Close()

	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Errorf("unexpected reading from closed connection")
	}

	_, err = clientAlice.OpenConn(ctx, "bob")
	if err == nil {
		t.Errorf("unexpected opening connection to closed server")
	}
}

func TestCloseByServer(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:50801"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv1, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
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
	relayClient := NewClient(serverCfg.ExposedAddress, hmacTokenStore, idAlice, iface.DefaultMTU)
	if err = relayClient.Connect(ctx); err != nil {
		log.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		if err := relayClient.Close(); err != nil {
			log.Errorf("failed to close client: %s", err)
		}
	}()

	disconnected := make(chan struct{})
	relayClient.SetOnDisconnectListener(func(_ string) {
		log.Infof("client disconnected")
		close(disconnected)
	})

	err = srv1.Shutdown(ctx)
	if err != nil {
		t.Fatalf("failed to close server: %s", err)
	}

	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		log.Errorf("timeout waiting for client to disconnect")
	}

	_, err = relayClient.OpenConn(ctx, "bob")
	if err == nil {
		t.Errorf("unexpected opening connection to closed server")
	}
}

func TestCloseByClient(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:50901"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
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
	relayClient := NewClient(serverCfg.ExposedAddress, hmacTokenStore, idAlice, iface.DefaultMTU)
	err = relayClient.Connect(ctx)
	if err != nil {
		log.Fatalf("failed to connect to server: %s", err)
	}

	err = relayClient.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}

	_, err = relayClient.OpenConn(ctx, "bob")
	if err == nil {
		t.Errorf("unexpected opening connection to closed server")
	}

	err = srv.Shutdown(ctx)
	if err != nil {
		t.Fatalf("failed to close server: %s", err)
	}
}

func TestCloseNotDrainedChannel(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:51001"
	serverCfg := newClientTestServerConfig(serverListenAddr)
	idAlice := "alice"
	idBob := "bob"
	srvCfg := server.ListenerConfig{Address: serverListenAddr}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
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

	// wait for servers to start
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, idAlice, iface.DefaultMTU)
	err = clientAlice.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err := clientAlice.Close()
		if err != nil {
			t.Errorf("failed to close Alice client: %s", err)
		}
	}()

	clientBob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, idBob, iface.DefaultMTU)
	err = clientBob.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err := clientBob.Close()
		if err != nil {
			t.Errorf("failed to close Bob client: %s", err)
		}
	}()

	connAliceToBob, err := clientAlice.OpenConn(ctx, idBob)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	connBobToAlice, err := clientBob.OpenConn(ctx, idAlice)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	payload := "hello bob, I am alice"
	// the internal channel buffer size is 2. So we should overflow it
	for i := 0; i < 5; i++ {
		_, err = connAliceToBob.Write([]byte(payload))
		if err != nil {
			t.Fatalf("failed to write to channel: %s", err)
		}

	}

	// wait for delivery
	time.Sleep(1 * time.Second)
	err = connBobToAlice.Close()
	if err != nil {
		t.Errorf("failed to close channel: %s", err)
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
