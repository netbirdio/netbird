package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/signal-dispatcher/dispatcher"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/metrics"
	"github.com/netbirdio/netbird/signal/peer"
)

const (
	labelType              = "type"
	labelTypeError         = "error"
	labelTypeNotConnected  = "not_connected"
	labelTypeNotRegistered = "not_registered"
	labelTypeStream        = "stream"
	labelTypeMessage       = "message"
	labelTypeTimeout       = "timeout"
	labelTypeDisconnected  = "disconnected"

	labelError                   = "error"
	labelErrorMissingId          = "missing_id"
	labelErrorMissingMeta        = "missing_meta"
	labelErrorFailedHeader       = "failed_header"
	labelErrorFailedRegistration = "failed_registration"

	labelRegistrationStatus   = "status"
	labelRegistrationFound    = "found"
	labelRegistrationNotFound = "not_found"

	sendTimeout = 10 * time.Second
)

var (
	ErrPeerRegisteredAgain = errors.New("peer registered again")
)

// Server an instance of a Signal server
type Server struct {
	registry *peer.Registry
	proto.UnimplementedSignalExchangeServer
	dispatcher *dispatcher.Dispatcher
	metrics    *metrics.AppMetrics

	successHeader metadata.MD

	sendTimeout time.Duration
}

// NewServer creates a new Signal server
func NewServer(ctx context.Context, meter metric.Meter, metricsPrefix ...string) (*Server, error) {
	appMetrics, err := metrics.NewAppMetrics(meter, metricsPrefix...)
	if err != nil {
		return nil, fmt.Errorf("creating app metrics: %v", err)
	}

	d, err := dispatcher.NewDispatcher(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("creating dispatcher: %v", err)
	}

	sTimeout := sendTimeout
	to := os.Getenv("NB_SIGNAL_SEND_TIMEOUT")
	if parsed, err := time.ParseDuration(to); err == nil && parsed > 0 {
		log.Trace("using custom send timeout ", parsed)
		sTimeout = parsed
	}

	s := &Server{
		dispatcher:    d,
		registry:      peer.NewRegistry(appMetrics),
		metrics:       appMetrics,
		successHeader: metadata.Pairs(proto.HeaderRegistered, "1"),
		sendTimeout:   sTimeout,
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
	ctx, cancel := context.WithCancel(context.Background())
	p, err := s.RegisterPeer(stream, cancel)
	if err != nil {
		return err
	}

	defer s.DeregisterPeer(p)

	// needed to confirm that the peer has been registered so that the client can proceed
	err = stream.SendHeader(s.successHeader)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedHeader)))
		return err
	}

	log.Debugf("peer connected [%s] [streamID %d] ", p.Id, p.StreamID)

	select {
	case <-stream.Context().Done():
		log.Debugf("peer stream closing [%s] [streamID %d] ", p.Id, p.StreamID)
		return nil
	case <-ctx.Done():
		return ErrPeerRegisteredAgain
	}
}

func (s *Server) RegisterPeer(stream proto.SignalExchange_ConnectStreamServer, cancel context.CancelFunc) (*peer.Peer, error) {
	log.Debugf("registering new peer")
	id := metadata.ValueFromIncomingContext(stream.Context(), proto.HeaderId)
	if id == nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorMissingId)))
		return nil, status.Errorf(codes.FailedPrecondition, "missing connection header: %s", proto.HeaderId)
	}

	p := peer.NewPeer(id[0], stream, cancel)
	if err := s.registry.Register(p); err != nil {
		return nil, err
	}
	err := s.dispatcher.ListenForMessages(stream.Context(), p.Id, s.forwardMessageToPeer)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedRegistration)))
		log.Errorf("error while registering message listener for peer [%s] %v", p.Id, err)
		return nil, status.Errorf(codes.Internal, "error while registering message listener")
	}
	return p, nil
}

func (s *Server) DeregisterPeer(p *peer.Peer) {
	log.Debugf("peer disconnected [%s] [streamID %d] ", p.Id, p.StreamID)
	s.metrics.PeerConnectionDuration.Record(p.Stream.Context(), int64(time.Since(p.RegisteredAt).Seconds()))
	s.registry.Deregister(p)
}

func (s *Server) forwardMessageToPeer(ctx context.Context, msg *proto.EncryptedMessage) {
	log.Tracef("forwarding a new message from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)
	getRegistrationStart := time.Now()

	// lookup the target peer where the message is going to
	dstPeer, found := s.registry.Get(msg.RemoteKey)

	if !found {
		s.metrics.GetRegistrationDelay.Record(ctx, float64(time.Since(getRegistrationStart).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelRegistrationStatus, labelRegistrationNotFound)))
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeNotConnected)))
		log.Tracef("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", msg.Key, msg.RemoteKey)
		// todo respond to the sender?
		return
	}

	s.metrics.GetRegistrationDelay.Record(ctx, float64(time.Since(getRegistrationStart).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelRegistrationStatus, labelRegistrationFound)))
	start := time.Now()

	sendResultChan := make(chan error, 1)
	go func() {
		select {
		case sendResultChan <- dstPeer.Stream.Send(msg):
			return
		case <-dstPeer.Stream.Context().Done():
			return
		}
	}()

	select {
	case err := <-sendResultChan:
		if err != nil {
			log.Tracef("error while forwarding message from peer [%s] to peer [%s]: %v", msg.Key, msg.RemoteKey, err)
			s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeError)))
			return
		}
		s.metrics.MessageForwardLatency.Record(ctx, float64(time.Since(start).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream)))
		s.metrics.MessagesForwarded.Add(ctx, 1)
		s.metrics.MessageSize.Record(ctx, int64(gproto.Size(msg)), metric.WithAttributes(attribute.String(labelType, labelTypeMessage)))

	case <-dstPeer.Stream.Context().Done():
		log.Tracef("failed to forward message from peer [%s] to peer [%s]: destination peer disconnected", msg.Key, msg.RemoteKey)
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeDisconnected)))

	case <-time.After(s.sendTimeout):
		dstPeer.Cancel() // cancel the peer context to trigger deregistration
		log.Tracef("failed to forward message from peer [%s] to peer [%s]: send timeout", msg.Key, msg.RemoteKey)
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeTimeout)))
	}
}
