package client_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	flow "github.com/netbirdio/netbird/flow/client"
	"github.com/netbirdio/netbird/flow/proto"
)

type testServer struct {
	proto.UnimplementedFlowServiceServer
	events         chan *proto.FlowEvent
	acks           chan *proto.FlowEventAck
	grpcSrv        *grpc.Server
	addr           string
	listener       *connTrackListener
	closeStream    chan struct{} // signal server to close the stream
	handlerDone    chan struct{} // signaled each time Events() exits
	handlerStarted chan struct{} // signaled each time Events() begins
}

// connTrackListener wraps a net.Listener to track accepted connections
// so tests can forcefully close them to simulate PROTOCOL_ERROR/RST_STREAM.
type connTrackListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *connTrackListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
	return c, nil
}

// sendRSTStream writes a raw HTTP/2 RST_STREAM frame with PROTOCOL_ERROR
// (error code 0x1) on every tracked connection. This produces the exact error:
//
//	rpc error: code = Internal desc = stream terminated by RST_STREAM with error code: PROTOCOL_ERROR
//
// HTTP/2 RST_STREAM frame format (9-byte header + 4-byte payload):
//
//	Length (3 bytes): 0x000004
//	Type   (1 byte):  0x03 (RST_STREAM)
//	Flags  (1 byte):  0x00
//	Stream ID (4 bytes): target stream (must have bit 31 clear)
//	Error Code (4 bytes): 0x00000001 (PROTOCOL_ERROR)
func (l *connTrackListener) connCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

func (l *connTrackListener) sendRSTStream(streamID uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()

	frame := make([]byte, 13) // 9-byte header + 4-byte payload
	// Length = 4 (3 bytes, big-endian)
	frame[0], frame[1], frame[2] = 0, 0, 4
	// Type = RST_STREAM (0x03)
	frame[3] = 0x03
	// Flags = 0
	frame[4] = 0x00
	// Stream ID (4 bytes, big-endian, bit 31 reserved = 0)
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	// Error Code = PROTOCOL_ERROR (0x1)
	binary.BigEndian.PutUint32(frame[9:13], 0x1)

	for _, c := range l.conns {
		_, _ = c.Write(frame)
	}
}

func newTestServer(t *testing.T) *testServer {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	listener := &connTrackListener{Listener: rawListener}

	s := &testServer{
		events:         make(chan *proto.FlowEvent, 100),
		acks:           make(chan *proto.FlowEventAck, 100),
		grpcSrv:        grpc.NewServer(),
		addr:           rawListener.Addr().String(),
		listener:       listener,
		closeStream:    make(chan struct{}, 1),
		handlerDone:    make(chan struct{}, 10),
		handlerStarted: make(chan struct{}, 10),
	}

	proto.RegisterFlowServiceServer(s.grpcSrv, s)

	go func() {
		if err := s.grpcSrv.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Logf("server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		s.grpcSrv.Stop()
	})

	return s
}

func (s *testServer) Events(stream proto.FlowService_EventsServer) error {
	defer func() {
		select {
		case s.handlerDone <- struct{}{}:
		default:
		}
	}()

	err := stream.Send(&proto.FlowEventAck{IsInitiator: true})
	if err != nil {
		return err
	}

	select {
	case s.handlerStarted <- struct{}{}:
	default:
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	go func() {
		defer cancel()
		for {
			event, err := stream.Recv()
			if err != nil {
				return
			}

			if !event.IsInitiator {
				select {
				case s.events <- event:
					ack := &proto.FlowEventAck{
						EventId: event.EventId,
					}
					select {
					case s.acks <- ack:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case ack := <-s.acks:
			if err := stream.Send(ack); err != nil {
				return err
			}
		case <-s.closeStream:
			return status.Errorf(codes.Internal, "server closing stream")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func TestReceive(t *testing.T) {
	server := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := client.Close()
		assert.NoError(t, err, "failed to close flow")
	})

	var ackCount atomic.Int32
	receiveDone := make(chan struct{})

	go func() {
		err := client.Receive(ctx, 1*time.Second, func(msg *proto.FlowEventAck) error {
			if !msg.IsInitiator && len(msg.EventId) > 0 {
				if ackCount.Add(1) >= 3 {
					close(receiveDone)
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("receive error: %v", err)
		}
	}()

	select {
	case <-server.handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stream to be established")
	}

	for i := 0; i < 3; i++ {
		eventID := uuid.New().String()

		// Create acknowledgment and send it to the flow through our test server
		ack := &proto.FlowEventAck{
			EventId: []byte(eventID),
		}

		select {
		case server.acks <- ack:
		case <-time.After(time.Second):
			t.Fatal("timeout sending ack")
		}
	}

	select {
	case <-receiveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for acks to be processed")
	}

	assert.Equal(t, int32(3), ackCount.Load())
}

func TestReceive_ContextCancellation(t *testing.T) {
	server := newTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := client.Close()
		assert.NoError(t, err, "failed to close flow")
	})

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	handlerCalled := false
	msgHandler := func(msg *proto.FlowEventAck) error {
		if !msg.IsInitiator {
			handlerCalled = true
		}
		return nil
	}

	err = client.Receive(ctx, 1*time.Second, msgHandler)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
	assert.False(t, handlerCalled)
}

func TestSend(t *testing.T) {
	server := newTestServer(t)

	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := client.Close()
		assert.NoError(t, err, "failed to close flow")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	ackReceived := make(chan struct{})

	go func() {
		err := client.Receive(ctx, 1*time.Second, func(ack *proto.FlowEventAck) error {
			if len(ack.EventId) > 0 && !ack.IsInitiator {
				close(ackReceived)
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("receive error: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	testEvent := &proto.FlowEvent{
		EventId:   []byte("test-event-id"),
		PublicKey: []byte("test-public-key"),
		FlowFields: &proto.FlowFields{
			FlowId:   []byte("test-flow-id"),
			Protocol: 6,
			SourceIp: []byte{192, 168, 1, 1},
			DestIp:   []byte{192, 168, 1, 2},
			ConnectionInfo: &proto.FlowFields_PortInfo{
				PortInfo: &proto.PortInfo{
					SourcePort: 12345,
					DestPort:   443,
				},
			},
		},
	}

	err = client.Send(testEvent)
	require.NoError(t, err)

	var receivedEvent *proto.FlowEvent
	select {
	case receivedEvent = <-server.events:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event to be received by server")
	}

	assert.Equal(t, testEvent.EventId, receivedEvent.EventId)
	assert.Equal(t, testEvent.PublicKey, receivedEvent.PublicKey)

	select {
	case <-ackReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ack to be received by flow")
	}
}

func TestNewClient_PermanentClose(t *testing.T) {
	server := newTestServer(t)

	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() {
		done <- client.Receive(ctx, 1*time.Second, func(msg *proto.FlowEventAck) error {
			return nil
		})
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, flow.ErrClientClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Receive did not return after Close — stuck in retry loop")
	}
}

func TestNewClient_CloseVerify(t *testing.T) {
	server := newTestServer(t)

	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() {
		done <- client.Receive(ctx, 1*time.Second, func(msg *proto.FlowEventAck) error {
			return nil
		})
	}()

	closeDone := make(chan struct{}, 1)
	go func() {
		_ = client.Close()
		closeDone <- struct{}{}
	}()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Receive did not return after Close — stuck in retry loop")
	}

	select {
	case <-closeDone:
		return
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return — blocked in retry loop")
	}

}

func TestClose_WhileReceiving(t *testing.T) {
	server := newTestServer(t)
	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)

	ctx := context.Background() // no timeout — intentional
	receiveDone := make(chan struct{})
	go func() {
		_ = client.Receive(ctx, 1*time.Second, func(msg *proto.FlowEventAck) error {
			return nil
		})
		close(receiveDone)
	}()

	// Wait for the server-side handler to confirm the stream is established.
	select {
	case <-server.handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stream to be established")
	}

	closeDone := make(chan struct{})
	go func() {
		_ = client.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		// Close returned — good
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked forever — Receive stuck in retry loop")
	}

	select {
	case <-receiveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Receive did not exit after Close")
	}
}

func TestReceive_ProtocolErrorStreamReconnect(t *testing.T) {
	server := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	client, err := flow.NewClient("http://"+server.addr, "test-payload", "test-signature", 1*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := client.Close()
		assert.NoError(t, err, "failed to close flow")
	})

	// Track acks received before and after server-side stream close
	var ackCount atomic.Int32
	receivedFirst := make(chan struct{})
	receivedAfterReconnect := make(chan struct{})

	go func() {
		err := client.Receive(ctx, 1*time.Second, func(msg *proto.FlowEventAck) error {
			if msg.IsInitiator || len(msg.EventId) == 0 {
				return nil
			}
			n := ackCount.Add(1)
			if n == 1 {
				close(receivedFirst)
			}
			if n == 2 {
				close(receivedAfterReconnect)
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("receive error: %v", err)
		}
	}()

	// Wait for stream to be established, then send first ack
	select {
	case <-server.handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stream to be established")
	}
	server.acks <- &proto.FlowEventAck{EventId: []byte("before-close")}

	select {
	case <-receivedFirst:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for first ack")
	}

	// Snapshot connection count before injecting the fault.
	connsBefore := server.listener.connCount()

	// Send a raw HTTP/2 RST_STREAM frame with PROTOCOL_ERROR on the TCP connection.
	// gRPC multiplexes streams on stream IDs 1, 3, 5, ... (odd, client-initiated).
	// Stream ID 1 is the client's first stream (our Events bidi stream).
	// This produces the exact error the client sees in production:
	//   "stream terminated by RST_STREAM with error code: PROTOCOL_ERROR"
	server.listener.sendRSTStream(1)

	// Wait for the old Events() handler to fully exit so it can no longer
	// drain s.acks and drop our injected ack on a broken stream.
	select {
	case <-server.handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("old Events() handler did not exit after RST_STREAM")
	}

	require.Eventually(t, func() bool {
		return server.listener.connCount() > connsBefore
	}, 5*time.Second, 50*time.Millisecond, "client did not open a new TCP connection after RST_STREAM")

	server.acks <- &proto.FlowEventAck{EventId: []byte("after-close")}

	select {
	case <-receivedAfterReconnect:
		// Client successfully reconnected and received ack after server-side stream close
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ack after server-side stream close — client did not reconnect")
	}

	assert.GreaterOrEqual(t, int(ackCount.Load()), 2, "should have received acks before and after stream close")
	assert.GreaterOrEqual(t, server.listener.connCount(), 2, "client should have created at least 2 TCP connections (original + reconnect)")
}
