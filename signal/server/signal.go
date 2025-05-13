package server

import (
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/signal-dispatcher/dispatcher"

	"github.com/netbirdio/netbird/signal/metrics"
	"github.com/netbirdio/netbird/signal/peer"
	"github.com/netbirdio/netbird/signal/proto"
)

const (
	labelType              = "type"
	labelTypeError         = "error"
	labelTypeNotConnected  = "not_connected"
	labelTypeNotRegistered = "not_registered"
	labelTypeStream        = "stream"
	labelTypeMessage       = "message"

	labelError             = "error"
	labelErrorMissingId    = "missing_id"
	labelErrorMissingMeta  = "missing_meta"
	labelErrorFailedHeader = "failed_header"

	labelRegistrationStatus   = "status"
	labelRegistrationFound    = "found"
	labelRegistrationNotFound = "not_found"
)

// Server an instance of a Signal server
type Server struct {
	registry *peer.Registry
	proto.UnimplementedSignalExchangeServer
	dispatcher *dispatcher.Dispatcher
	metrics    *metrics.AppMetrics
}

// NewServer creates a new Signal server
func NewServer(ctx context.Context, meter metric.Meter) (*Server, error) {
	appMetrics, err := metrics.NewAppMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("creating app metrics: %v", err)
	}

	d, err := dispatcher.NewDispatcher(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("creating dispatcher: %v", err)
	}

	s := &Server{
		dispatcher: d,
		registry:   peer.NewRegistry(appMetrics),
		metrics:    appMetrics,
	}

	return s, nil
}

// Send forwards a message to the signal peer
func (s *Server) Send(ctx context.Context, msg *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.Tracef("received a new message to send from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)

	if _, found := s.registry.Get(msg.RemoteKey); found {
		s.forwardMessageToPeer(ctx, msg)
		return &proto.EncryptedMessage{}, nil
	}

	return s.dispatcher.SendMessage(ctx, msg)
}

// ConnectStream connects to the exchange stream
func (s *Server) ConnectStream(stream proto.SignalExchange_ConnectStreamServer) error {
	p, err := s.RegisterPeer(stream)
	if err != nil {
		return err
	}

	defer s.DeregisterPeer(p)

	// needed to confirm that the peer has been registered so that the client can proceed
	header := metadata.Pairs(proto.HeaderRegistered, "1")
	err = stream.SendHeader(header)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedHeader)))
		return err
	}

	log.Debugf("peer connected [%s] [streamID %d] ", p.Id, p.StreamID)

	for {
		select {
		case <-stream.Context().Done():
			log.Debugf("stream closed for peer [%s] [streamID %d] due to context cancellation", p.Id, p.StreamID)
			return stream.Context().Err()
		default:
			// read incoming messages
			msg, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			log.Tracef("Received a response from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)

			_, err = s.dispatcher.SendMessage(stream.Context(), msg)
			if err != nil {
				log.Debugf("error while sending message from peer [%s] to peer [%s] %v", msg.Key, msg.RemoteKey, err)
			}
		}
	}
}

func (s *Server) RegisterPeer(stream proto.SignalExchange_ConnectStreamServer) (*peer.Peer, error) {
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

	p := peer.NewPeer(id[0], stream)
	s.registry.Register(p)
	s.dispatcher.ListenForMessages(stream.Context(), p.Id, s.forwardMessageToPeer)
	return p, nil
}

func (s *Server) DeregisterPeer(p *peer.Peer) {
	log.Debugf("peer disconnected [%s] [streamID %d] ", p.Id, p.StreamID)
	s.registry.Deregister(p)
	s.metrics.PeerConnectionDuration.Record(p.Stream.Context(), int64(time.Since(p.RegisteredAt).Seconds()))
}

func (s *Server) forwardMessageToPeer(ctx context.Context, msg *proto.EncryptedMessage) {
	log.Tracef("forwarding a new message from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)
	getRegistrationStart := time.Now()

	// lookup the target peer where the message is going to
	dstPeer, found := s.registry.Get(msg.RemoteKey)

	if !found {
		s.metrics.GetRegistrationDelay.Record(ctx, float64(time.Since(getRegistrationStart).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelRegistrationStatus, labelRegistrationNotFound)))
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeNotConnected)))
		log.Debugf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", msg.Key, msg.RemoteKey)
		// todo respond to the sender?
		return
	}

	s.metrics.GetRegistrationDelay.Record(ctx, float64(time.Since(getRegistrationStart).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelRegistrationStatus, labelRegistrationFound)))
	start := time.Now()

	// forward the message to the target peer
	if err := dstPeer.Stream.Send(msg); err != nil {
		log.Tracef("error while forwarding message from peer [%s] to peer [%s] %v", msg.Key, msg.RemoteKey, err)
		// todo respond to the sender?
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeError)))
		return
	}

	// in milliseconds
	s.metrics.MessageForwardLatency.Record(ctx, float64(time.Since(start).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream)))
	s.metrics.MessagesForwarded.Add(ctx, 1)
	s.metrics.MessageSize.Record(ctx, int64(gproto.Size(msg)), metric.WithAttributes(attribute.String(labelType, labelTypeMessage)))
}
