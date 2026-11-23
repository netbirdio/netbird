package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/signal-dispatcher/dispatcher"

	"github.com/netbirdio/netbird/shared/lifecycle"
	"github.com/netbirdio/netbird/shared/profiling"
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
	labelTypeTimeout       = "timeout"
	labelTypeDisconnected  = "disconnected"
	labelTypeDispatch      = "dispatch"

	labelResult          = "result"
	labelResultDelivered = "delivered"

	labelError                   = "error"
	labelErrorMissingId          = "missing_id"
	labelErrorMissingMeta        = "missing_meta"
	labelErrorFailedHeader       = "failed_header"
	labelErrorFailedRegistration = "failed_registration"
	labelErrorAlreadyRegistered  = "already_registered"

	labelRegistrationStatus   = "status"
	labelRegistrationFound    = "found"
	labelRegistrationNotFound = "not_found"

	labelRoute       = "route"
	labelRouteLocal  = "local"
	labelRouteRemote = "remote"

	sendTimeout = 10 * time.Second

	applicationName = "signal"

	// EnvFlushAfterRegister opts into sending a placeholder frame immediately
	// after the registration header on ConnectStream, for proxies that buffer
	// a headers-only stream until a DATA frame follows it. See the comment on
	// flushAfterRegister's use in ConnectStream for details.
	EnvFlushAfterRegister = "NB_SIGNAL_FLUSH_AFTER_REGISTER"
)

var (
	ErrPeerRegisteredAgain = errors.New("peer registered again")
)

// Server an instance of a Signal server
type Server struct {
	lifecycle.StopHandlers
	registry *peer.Registry
	proto.UnimplementedSignalExchangeServer
	dispatcher *dispatcher.Dispatcher
	metrics    *metrics.AppMetrics

	successHeader metadata.MD

	sendTimeout time.Duration

	flushAfterRegister bool
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
		dispatcher:         d,
		registry:           peer.NewRegistry(appMetrics),
		metrics:            appMetrics,
		successHeader:      metadata.Pairs(proto.HeaderRegistered, "1"),
		sendTimeout:        sTimeout,
		flushAfterRegister: flushAfterRegisterFromEnv(),
	}

	stopProfiling := profiling.Start(applicationName)
	s.OnStop(stopProfiling)

	return s, nil
}

func flushAfterRegisterFromEnv() bool {
	val := os.Getenv(EnvFlushAfterRegister)
	if val == "" {
		return false
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvFlushAfterRegister, err)
		return false
	}
	return enabled
}

// Stop runs the handlers registered with OnStop.
func (s *Server) Stop() {
	s.RunStopHandlers()
}

// Send forwards a message to the signal peer
func (s *Server) Send(ctx context.Context, msg *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.Tracef("received a new message to send from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)

	s.metrics.SendInflight.Add(ctx, 1)
	defer s.metrics.SendInflight.Add(ctx, -1)

	if _, found := s.registry.Get(msg.RemoteKey); found {
		s.recordReceived(ctx, msg, labelRouteLocal)
		s.recordSendResult(ctx, labelRouteLocal, s.forwardMessageToPeer(ctx, msg))
		return &proto.EncryptedMessage{}, nil
	}

	s.recordReceived(ctx, msg, labelRouteRemote)
	resp, err := s.dispatcher.SendMessage(ctx, msg)
	if err != nil {
		s.recordSendResult(ctx, labelRouteRemote, labelTypeDispatch)
		return resp, err
	}
	s.recordSendResult(ctx, labelRouteRemote, labelResultDelivered)
	return resp, nil
}

// recordReceived counts msg as received through Send and records its size. A
// self-addressed message is also counted as a probe: the body is encrypted, so
// the addressing is the only thing that identifies a client heartbeat.
func (s *Server) recordReceived(ctx context.Context, msg *proto.EncryptedMessage, route string) {
	attrs := metric.WithAttributes(attribute.String(labelRoute, route))
	s.metrics.MessagesReceived.Add(ctx, 1, attrs)
	s.metrics.MessageSize.Record(ctx, int64(gproto.Size(msg)), attrs)
	if msg.Key == msg.RemoteKey {
		s.metrics.ProbeMessages.Add(ctx, 1, attrs)
	}
}

// recordSendResult counts the outcome of a message received through Send.
func (s *Server) recordSendResult(ctx context.Context, route, result string) {
	if result == labelResultDelivered {
		s.metrics.SendSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String(labelRoute, route)))
		return
	}
	s.metrics.SendFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelRoute, route), attribute.String(labelType, result)))
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

	if s.flushAfterRegister {
		// Some reverse proxies / load balancers buffer the HEADERS frame above
		// until a DATA frame follows it on the same stream - reproduced with an
		// AWS ALB gRPC target group. ConnectStream is otherwise a pure
		// server-push stream that can go silent for minutes after registration,
		// so on such a proxy the registration header can be held indefinitely,
		// leaving the client waiting forever even though the server already
		// sent it. Sending an immediate placeholder message right behind the
		// header forces the proxy to flush both together. The key is
		// deliberately not a valid WireGuard key, so the client fails to parse/
		// decrypt it and drops it (see shared/signal/client/worker.go); it costs
		// one error-level "failed to decrypt message" log line on the client per
		// connection, which is the accepted trade-off for an opt-in mitigation.
		// Sent via p.Send (not stream.Send directly) so it serializes with any
		// message forwardMessageToPeer is concurrently relaying to this same
		// peer - gRPC forbids concurrent SendMsg calls on one ServerStream.
		// Opt-in via NB_SIGNAL_FLUSH_AFTER_REGISTER since most deployments
		// don't need it.
		if err := p.Send(&proto.EncryptedMessage{Key: "signal-server-flush", RemoteKey: p.Id}); err != nil {
			log.Debugf("failed to send post-registration flush frame to peer [%s]: %v", p.Id, err)
		}
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
	start := time.Now()
	id := metadata.ValueFromIncomingContext(stream.Context(), proto.HeaderId)
	if id == nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorMissingId)))
		return nil, status.Errorf(codes.FailedPrecondition, "missing connection header: %s", proto.HeaderId)
	}

	p := peer.NewPeer(id[0], stream, cancel)
	if err := s.registry.Register(p); err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorAlreadyRegistered)))
		return nil, err
	}
	err := s.dispatcher.ListenForMessages(stream.Context(), p.Id, func(ctx context.Context, msg *proto.EncryptedMessage) {
		s.forwardMessageToPeer(ctx, msg)
	})
	if err != nil {
		s.registry.Deregister(p)
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedRegistration)))
		log.Errorf("error while registering message listener for peer [%s] %v", p.Id, err)
		return nil, status.Errorf(codes.Internal, "error while registering message listener")
	}
	s.metrics.RegistrationDelay.Record(stream.Context(), float64(time.Since(start).Nanoseconds())/1e6)
	return p, nil
}

func (s *Server) DeregisterPeer(p *peer.Peer) {
	log.Debugf("peer disconnected [%s] [streamID %d] ", p.Id, p.StreamID)
	s.metrics.PeerConnectionDuration.Record(p.Stream.Context(), int64(time.Since(p.RegisteredAt).Seconds()))
	s.registry.Deregister(p)
}

// forwardMessageToPeer writes msg to its destination stream on this node and
// returns labelResultDelivered or the failure type.
func (s *Server) forwardMessageToPeer(ctx context.Context, msg *proto.EncryptedMessage) string {
	log.Tracef("forwarding a new message from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)
	getRegistrationStart := time.Now()

	// lookup the target peer where the message is going to
	dstPeer, found := s.registry.Get(msg.RemoteKey)

	if !found {
		s.metrics.GetRegistrationDelay.Record(ctx, float64(time.Since(getRegistrationStart).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelRegistrationStatus, labelRegistrationNotFound)))
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeNotConnected)))
		log.Tracef("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", msg.Key, msg.RemoteKey)
		// todo respond to the sender?
		return labelTypeNotConnected
	}

	s.metrics.GetRegistrationDelay.Record(ctx, float64(time.Since(getRegistrationStart).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelRegistrationStatus, labelRegistrationFound)))
	start := time.Now()

	sendResultChan := make(chan error, 1)
	go func() {
		select {
		case sendResultChan <- dstPeer.Send(msg):
			return
		case <-dstPeer.Stream.Context().Done():
			return
		}
	}()

	var result string
	select {
	case err := <-sendResultChan:
		result = labelResultDelivered
		if err != nil {
			log.Tracef("error while forwarding message from peer [%s] to peer [%s]: %v", msg.Key, msg.RemoteKey, err)
			result = labelTypeError
		}

	case <-dstPeer.Stream.Context().Done():
		log.Tracef("failed to forward message from peer [%s] to peer [%s]: destination peer disconnected", msg.Key, msg.RemoteKey)
		result = labelTypeDisconnected

	case <-time.After(s.sendTimeout):
		dstPeer.Cancel() // cancel the peer context to trigger deregistration
		log.Tracef("failed to forward message from peer [%s] to peer [%s]: send timeout", msg.Key, msg.RemoteKey)
		result = labelTypeTimeout
	}

	s.metrics.MessageForwardLatency.Record(ctx, float64(time.Since(start).Nanoseconds())/1e6, metric.WithAttributes(attribute.String(labelType, labelTypeStream), attribute.String(labelResult, result)))
	if result == labelResultDelivered {
		s.metrics.MessagesForwarded.Add(ctx, 1)
	} else {
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, result)))
	}
	return result
}
