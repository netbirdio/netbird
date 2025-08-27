package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	gpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/peer"
)

type mockSignalExchange_ConnectStreamServer struct {
	ctx         context.Context
	recvChan    chan *proto.EncryptedMessage
	sentHeaders metadata.MD
	mu          sync.Mutex
}

func (m *mockSignalExchange_ConnectStreamServer) Send(*proto.EncryptedMessage) error {
	return nil
}

func (m *mockSignalExchange_ConnectStreamServer) Recv() (*proto.EncryptedMessage, error) {
	select {
	case <-m.ctx.Done():
		return nil, m.ctx.Err()
	case msg, ok := <-m.recvChan:
		if !ok {
			return nil, errors.New("recv chan closed")
		}
		return msg, nil
	}
}

func (m *mockSignalExchange_ConnectStreamServer) SendHeader(md metadata.MD) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentHeaders = metadata.Join(m.sentHeaders, md)
	return nil
}

func (m *mockSignalExchange_ConnectStreamServer) SetHeader(metadata.MD) error {
	return errors.New("SetHeader not implemented on mock server stream")
}

func (m *mockSignalExchange_ConnectStreamServer) SetTrailer(metadata.MD) {}

func (m *mockSignalExchange_ConnectStreamServer) Context() context.Context {
	return m.ctx
}

func (m *mockSignalExchange_ConnectStreamServer) SendMsg(im interface{}) error {
	msg, ok := im.(*proto.EncryptedMessage)
	if !ok {
		return errors.New("invalid message type for SendMsg")
	}
	return m.Send(msg)
}

func (m *mockSignalExchange_ConnectStreamServer) RecvMsg(im interface{}) error {
	msg, err := m.Recv()
	if err != nil {
		return err
	}
	*(im.(**proto.EncryptedMessage)) = msg
	return nil
}

var benchServer *Server

func setupBenchServer(tb testing.TB) {
	if benchServer == nil {
		meter := noop.NewMeterProvider().Meter("benchmark")
		var err error
		benchServer, err = NewServer(context.Background(), meter) //
		if err != nil {
			tb.Fatalf("Failed to create server for benchmark: %v", err)
		}
	}
}

func BenchmarkConnectStream(b *testing.B) {
	setupBenchServer(b)

	body := func(b *testing.B, fn func(stream proto.SignalExchange_ConnectStreamServer) error, i int) {
		b.StopTimer()
		peerID := "testpeer-" + string(rune(i))
		md := metadata.New(map[string]string{proto.HeaderId: peerID})
		ctx := metadata.NewIncomingContext(context.Background(), md)
		p := &gpeer.Peer{Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}}
		ctx = gpeer.NewContext(ctx, p)
		recvChanForPeer := make(chan *proto.EncryptedMessage)

		mockStream := &mockSignalExchange_ConnectStreamServer{
			ctx:      ctx,
			recvChan: recvChanForPeer,
		}
		streamCtx, cancelStream := context.WithCancel(ctx)
		mockStream.ctx = streamCtx
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancelStream()
		}()

		b.StartTimer()
		_ = fn(mockStream)
	}
	b.Run("old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			body(b, benchServer.connectStreamPool, i)
		}
	})
	b.Run("new peer pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			body(b, benchServer.ConnectStream, i)
		}
	})
}

func (s *Server) connectStreamPool(stream proto.SignalExchange_ConnectStreamServer) error {
	p, err := s.registerPeer(stream)
	if err != nil {
		return err
	}

	defer s.deregisterPeer(p)

	// needed to confirm that the peer has been registered so that the client can proceed
	header := metadata.Pairs(proto.HeaderRegistered, "1")
	err = stream.SendHeader(header)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedHeader)))
		return err
	}

	log.Debugf("peer connected [%s] [streamID %d] ", p.Id, p.StreamID)

	<-stream.Context().Done()
	log.Debugf("peer stream closing [%s] [streamID %d] ", p.Id, p.StreamID)
	return nil
}

func (s *Server) registerPeer(stream proto.SignalExchange_ConnectStreamServer) (*peer.Peer, error) {
	log.Debugf("registering new peer")
	meta, hasMeta := metadata.FromIncomingContext(stream.Context())
	if !hasMeta {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorMissingMeta)))
		return nil, status.Errorf(codes.FailedPrecondition, "missing connection stream meta")
	}

	id, found := meta[proto.HeaderId]
	if !found {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorMissingId)))
		return nil, status.Errorf(codes.FailedPrecondition, "missing connection header: %s", proto.HeaderId)
	}

	_, cancel := context.WithCancel(context.Background())
	p := peer.NewPeer(id[0], stream, cancel)
	s.registry.Register(p)
	err := s.dispatcher.ListenForMessages(stream.Context(), p.Id, s.forwardMessageToPeer)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedRegistration)))
		log.Errorf("error while registering message listener for peer [%s] %v", p.Id, err)
		return nil, status.Errorf(codes.Internal, "error while registering message listener")
	}
	return p, nil
}

func (s *Server) deregisterPeer(p *peer.Peer) {
	log.Debugf("peer disconnected [%s] [streamID %d] ", p.Id, p.StreamID)
	s.metrics.PeerConnectionDuration.Record(p.Stream.Context(), int64(time.Since(p.RegisteredAt).Seconds()))
	s.registry.Deregister(p)
}
