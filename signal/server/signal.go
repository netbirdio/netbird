package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
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
	"github.com/netbirdio/netbird/shared/testhb"
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

	applicationName = "signal"

	// TestHeartbeatKey marks a test-only heartbeat sent to a peer on its own
	// stream when NB_TEST_HB_MODE is set. The body is empty.
	TestHeartbeatKey = "netbird-test-heartbeat"
	// TestGoingAwayKey tells a peer that the server is shutting down, so the
	// client reconnects at once. The body is empty.
	TestGoingAwayKey = "netbird-test-going-away"

	// goingAwayTimeout caps how long shutdown waits for the going-away sends.
	goingAwayTimeout = 2 * time.Second
)

var (
	ErrPeerRegisteredAgain = errors.New("peer registered again")

	errGoingAway = status.Error(codes.Unavailable, "signal server is shutting down")
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

	// draining is set by GoingAway. New streams are refused from then on.
	draining atomic.Bool
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

	stopProfiling := profiling.Start(applicationName)
	s.OnStop(stopProfiling)

	return s, nil
}

// Stop runs the handlers registered with OnStop.
func (s *Server) Stop() {
	s.RunStopHandlers()
}

// GoingAway tells every connected peer that this server is shutting down and
// refuses new streams from then on. A Go reverse proxy in front may not pass on
// the end of a bidi stream at Stop, but it does pass data, so the client learns
// about the shutdown from this message instead of its receive watchdog.
func (s *Server) GoingAway() {
	s.draining.Store(true)

	var peers []*peer.Peer
	s.registry.Peers.Range(func(_, v any) bool {
		peers = append(peers, v.(*peer.Peer))
		return true
	})

	var sent, failed atomic.Int32
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p *peer.Peer) {
			defer wg.Done()
			if err := p.Send(&proto.EncryptedMessage{Key: TestGoingAwayKey, RemoteKey: p.Id}); err != nil {
				log.Debugf("going away to [%s] failed: %v", p.Id, err)
				failed.Add(1)
				return
			}
			sent.Add(1)
		}(p)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(goingAwayTimeout):
		log.Warnf("going away: sends still pending after %s", goingAwayTimeout)
	}
	log.Infof("signal going away: notified %d of %d peers, %d failed", sent.Load(), len(peers), failed.Load())
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
	if s.draining.Load() {
		return errGoingAway
	}
	hbArrival := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	p, err := s.RegisterPeer(stream, cancel)
	if err != nil {
		return err
	}

	defer s.DeregisterPeer(p)

	// GoingAway may have listed the peers before this one registered.
	if s.draining.Load() {
		return errGoingAway
	}

	// needed to confirm that the peer has been registered so that the client can proceed
	err = stream.SendHeader(s.successHeader)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedHeader)))
		return err
	}

	log.Debugf("peer connected [%s] [streamID %d] ", p.Id, p.StreamID)

	go drainStream(stream)

	hbCtx, hbCancel := context.WithCancel(stream.Context())
	defer hbCancel()
	s.startTestHeartbeat(hbCtx, p, testHBClientSchedule(stream.Context(), hbArrival))

	select {
	case <-stream.Context().Done():
		log.Debugf("peer stream closing [%s] [streamID %d] ", p.Id, p.StreamID)
		return nil
	case <-ctx.Done():
		return ErrPeerRegisteredAgain
	}
}

// drainStream reads and drops what the client writes on its stream. Clients write
// on it only to probe the path, and unread data would fill the stream window.
func drainStream(stream proto.SignalExchange_ConnectStreamServer) {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return
		}
		if testhb.Enabled() && testhb.SignalBlackhole() {
			log.Infof("testhb: blackhole dropped stream message from [%s]", msg.GetKey())
		}
	}
}

// testHBClientSchedule reads the test heartbeat schedule from the stream metadata.
// arrival is the wall time when ConnectStream started.
func testHBClientSchedule(ctx context.Context, arrival time.Time) testhb.ClientSchedule {
	if !testhb.Enabled() {
		return testhb.ClientSchedule{}
	}
	v := metadata.ValueFromIncomingContext(ctx, testhb.MetadataKey)
	if len(v) == 0 {
		return testhb.ClientSchedule{}
	}
	return testhb.ClientScheduleFor(testhb.ServiceSignal, v[0], arrival)
}

// startTestHeartbeat sends TestHeartbeatKey messages to the peer on the
// testhb schedule until ctx is done. It does nothing when testhb is off.
// Sends go through Peer.Send, so they never race forwarded messages.
func (s *Server) startTestHeartbeat(ctx context.Context, p *peer.Peer, cs testhb.ClientSchedule) {
	key := testhb.PhaseKey(p.Id)
	tick := testhb.TickerWithClient(ctx, key, testhb.ServiceSignal, cs)
	if tick == nil {
		return
	}
	if cs.OK {
		log.Infof("testhb: client schedule svc=signal key=%s p=%d period=%d skew=%d",
			key, cs.PhaseMs, int64(cs.Period/time.Second), cs.SkewMs)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				if testhb.Muted(testhb.ServiceSignal) {
					log.Infof("testhb: muted signal heartbeat key=%s", key)
					continue
				}
				now := time.Now()
				if err := p.Send(&proto.EncryptedMessage{Key: TestHeartbeatKey, RemoteKey: p.Id}); err != nil {
					log.Debugf("testhb: signal heartbeat to [%s] failed: %v", p.Id, err)
					continue
				}
				mode := testhb.CurrentMode()
				log.Infof("testhb: sent signal heartbeat key=%s mode=%s t=%d%s", key, mode, now.UnixMilli(), testhb.LogSuffix(mode, cs))
			}
		}
	}()
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
	if testhb.Enabled() && testhb.SignalBlackhole() {
		log.Infof("testhb: blackhole dropped message from [%s] to [%s]", msg.Key, msg.RemoteKey)
		return
	}
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
		case sendResultChan <- dstPeer.Send(msg):
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
