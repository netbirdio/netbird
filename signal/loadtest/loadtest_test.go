package loadtest

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

func TestSignalLoadTest_SinglePair(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServer(t, ctx)
	defer grpcServer.Stop()

	sender, err := NewClient(serverAddr, "sender-peer-id")
	require.NoError(t, err)
	defer sender.Close()

	receiver, err := NewClient(serverAddr, "receiver-peer-id")
	require.NoError(t, err)
	defer receiver.Close()

	err = sender.Connect()
	require.NoError(t, err, "Sender should connect successfully")

	err = receiver.Connect()
	require.NoError(t, err, "Receiver should connect successfully")

	time.Sleep(100 * time.Millisecond)

	testMessage := []byte("test message payload")

	t.Log("Sending message from sender to receiver")
	err = sender.SendMessage("receiver-peer-id", testMessage)
	require.NoError(t, err, "Sender should send message successfully")

	t.Log("Waiting for receiver to receive message")

	receiveDone := make(chan struct{})
	var msg *proto.EncryptedMessage
	var receiveErr error

	go func() {
		msg, receiveErr = receiver.ReceiveMessage()
		close(receiveDone)
	}()

	select {
	case <-receiveDone:
		require.NoError(t, receiveErr, "Receiver should receive message")
		require.NotNil(t, msg, "Received message should not be nil")
		require.Greater(t, len(msg.Body), 0, "Encrypted message body size should be greater than 0")
		require.Equal(t, "sender-peer-id", msg.Key)
		require.Equal(t, "receiver-peer-id", msg.RemoteKey)
		t.Log("Message received successfully")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for message")
	}
}

func startTestSignalServer(t *testing.T, ctx context.Context) (*grpc.Server, string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()

	signalServer, err := server.NewServer(ctx, otel.Meter("test"))
	require.NoError(t, err)

	proto.RegisterSignalExchangeServer(grpcServer, signalServer)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	return grpcServer, fmt.Sprintf("http://%s", listener.Addr().String())
}
