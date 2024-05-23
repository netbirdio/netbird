package test

import (
	"net"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/relay/server"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", "console")
	code := m.Run()
	os.Exit(code)
}

func TestClient(t *testing.T) {
	addr := "localhost:1234"
	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	clientAlice := client.NewClient(addr, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientAlice.Close()

	clientPlaceHolder := client.NewClient(addr, "clientPlaceHolder")
	err = clientPlaceHolder.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientPlaceHolder.Close()

	clientBob := client.NewClient(addr, "bob")
	err = clientBob.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer clientBob.Close()

	connAliceToBob, err := clientAlice.OpenConn("bob")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

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

func TestRegistration(t *testing.T) {
	addr := "localhost:1234"
	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	clientAlice := client.NewClient(addr, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Fatalf("failed to connect to server: %s", err)
	}
	defer func() {
		err = clientAlice.Close()
		if err != nil {
			t.Errorf("failed to close conn: %s", err)
		}
	}()
}

func TestRegistrationTimeout(t *testing.T) {
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 1234,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		t.Fatalf("failed to bind UDP server: %s", err)
	}
	defer udpListener.Close()

	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: 1234,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		t.Fatalf("failed to bind TCP server: %s", err)
	}
	defer tcpListener.Close()

	clientAlice := client.NewClient("127.0.0.1:1234", "alice")
	err = clientAlice.Connect()
	if err == nil {
		t.Errorf("failed to connect to server: %s", err)
	}
	defer func() {
		err = clientAlice.Close()
		if err != nil {
			t.Errorf("failed to close conn: %s", err)
		}
	}()
}

func TestEcho(t *testing.T) {
	idAlice := "alice"
	idBob := "bob"
	addr := "localhost:1234"
	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	clientAlice := client.NewClient(addr, idAlice)
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

	clientBob := client.NewClient(addr, idBob)
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
	addr := "localhost:1234"
	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	clientAlice := client.NewClient(addr, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}
	defer func() {
		log.Infof("closing client")
		err := clientAlice.Close()
		if err != nil {
			t.Errorf("failed to close client: %s", err)
		}
	}()

	_, err = clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}
}

func TestBindReconnect(t *testing.T) {
	addr := "localhost:1234"
	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
		if err != nil {
			t.Errorf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		log.Infof("closing server")
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	clientAlice := client.NewClient(addr, "alice")
	err := clientAlice.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	_, err = clientAlice.OpenConn("bob")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	clientBob := client.NewClient(addr, "bob")
	err = clientBob.Connect()
	if err != nil {
		t.Errorf("failed to connect to server: %s", err)
	}

	chBob, err := clientBob.OpenConn("alice")
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	log.Infof("closing client")
	err = clientAlice.Close()
	if err != nil {
		t.Errorf("failed to close client: %s", err)
	}

	clientAlice = client.NewClient(addr, "alice")
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
