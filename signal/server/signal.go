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

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/alignedhb/phasectl"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/lifecycle"
	"github.com/netbirdio/netbird/shared/profiling"
	"github.com/netbirdio/netbird/shared/relay/messages"
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

	applicationName = "signal"

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

	// phaseVerifier checks the phases Management signed. Without it every
	// aligned heartbeat request is refused and streams stay stock.
	phaseVerifier atomic.Pointer[phasesig.Verifier]
	// periodLimits bound the aligned heartbeat period, nil for the defaults.
	periodLimits atomic.Pointer[alignedhb.PeriodLimits]
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

// SetPhaseVerifier sets the verifier for the aligned heartbeat phases that
// clients hand over when their streams open. It applies to streams opened after
// the call.
func (s *Server) SetPhaseVerifier(v *phasesig.Verifier) {
	s.phaseVerifier.Store(v)
}

// SetPeriodLimits sets the limits the aligned heartbeat period is clamped to.
// They may only narrow the default range and must match the limits of
// Management, which signs phases for the clamped period. Without a call the
// defaults apply.
func (s *Server) SetPeriodLimits(l alignedhb.PeriodLimits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	s.periodLimits.Store(&l)
	return nil
}

// Stop runs the handlers registered with OnStop.
func (s *Server) Stop() {
	s.RunStopHandlers()
}

// GoingAway tells every peer whose stream got the aligned heartbeat answer that
// this server is shutting down, and refuses new streams from then on. A Go
// reverse proxy in front may not pass on the end of a bidi stream at Stop, but
// it does pass data, so the client learns about the shutdown from this message
// instead of its receive watchdog. Stock peers get no message: they would try to
// decrypt it, and their stream ends at Stop as before.
func (s *Server) GoingAway() {
	s.draining.Store(true)

	var peers []*peer.Peer
	s.registry.Peers.Range(func(_, v any) bool {
		if p := v.(*peer.Peer); p.AlignedHeartbeat() {
			peers = append(peers, p)
		}
		return true
	})

	var sent, failed atomic.Int32
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p *peer.Peer) {
			defer wg.Done()
			if err := p.Send(goingAwayMessage(p.Id)); err != nil {
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
	log.Infof("signal going away: notified %d of %d aligned heartbeat peers, %d failed", sent.Load(), len(peers), failed.Load())
}

// Send forwards a message to the signal peer
func (s *Server) Send(ctx context.Context, msg *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	log.Tracef("received a new message to send from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)

	if _, found := s.registry.Get(msg.RemoteKey); found {
		s.forwardMessageToPeer(ctx, msg)
		return &proto.EncryptedMessage{}, nil
	}

	// The instance that delivers the message may run a version that does not
	// strip the server fields.
	return s.dispatcher.SendMessage(ctx, stripServerFields(msg))
}

// ConnectStream connects to the exchange stream
func (s *Server) ConnectStream(stream proto.SignalExchange_ConnectStreamServer) error {
	if s.draining.Load() {
		return errGoingAway
	}
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

	answer := s.alignedHeartbeatAnswer(stream.Context(), p.Id)

	// needed to confirm that the peer has been registered so that the client can proceed
	err = stream.SendHeader(s.registrationHeader(answer))
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedHeader)))
		return err
	}

	if answer != nil {
		p.MarkAlignedHeartbeat()
		// GoingAway may have listed the peers before the mark: it then skipped
		// this stream, so end it here.
		if s.draining.Load() {
			return errGoingAway
		}
	}

	log.Debugf("peer connected [%s] [streamID %d] ", p.Id, p.StreamID)

	phase := newStreamPhase(p.Id, answer, s.metrics.AlignedHeartbeat)
	// Clients write on the stream only after the server answered, so a stock
	// stream needs no reader.
	if phase != nil {
		go s.readStream(stream, phase)
	}

	stopHeartbeat := s.startAlignedHeartbeat(stream.Context(), p, phase)
	defer stopHeartbeat()

	select {
	case <-stream.Context().Done():
		log.Debugf("peer stream closing [%s] [streamID %d] ", p.Id, p.StreamID)
		return nil
	case <-ctx.Done():
		return ErrPeerRegisteredAgain
	}
}

// readStream reads what the client writes on its stream. Phase requests go to
// phase, anything else is dropped: clients write other frames only to probe the
// path, and unread data would fill the stream window.
func (s *Server) readStream(stream proto.SignalExchange_ConnectStreamServer, phase *streamPhase) {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return
		}
		if req := msg.GetPhaseRequest(); req != nil {
			phase.handleRequest(req, s.phaseVerifier.Load(), s.loadPeriodLimits(), time.Now())
		}
	}
}

// alignedHeartbeatAnswer reads the aligned heartbeat request from the stream
// metadata and returns the answer for the peer. It is nil, and the stream stays
// stock, when the client did not ask, sent a value this server cannot read, or
// the server has no phase verifier. Without a valid signed phase the answer
// carries only the period: the stream stays stock until the client sends one.
func (s *Server) alignedHeartbeatAnswer(ctx context.Context, peerID string) *streamAnswer {
	v := metadata.ValueFromIncomingContext(ctx, alignedhb.MetadataKey)
	if len(v) == 0 {
		return nil
	}
	req, err := alignedhb.ParseStreamRequest(v[0])
	if err != nil {
		log.Debugf("ignoring aligned heartbeat request from [%s]: %v", peerID, err)
		return nil
	}
	verifier := s.phaseVerifier.Load()
	if verifier == nil {
		log.Tracef("ignoring aligned heartbeat request from [%s]: no phase verifier configured", peerID)
		return nil
	}
	limits := s.loadPeriodLimits()
	period := limits.Clamp(req.Period)
	if period != req.Period {
		log.Debugf("aligned heartbeat period %s from [%s] clamped to %s", req.Period, peerID, period)
	}
	pending := &streamAnswer{period: period}
	if req.Signed == nil {
		log.Tracef("aligned heartbeat request from [%s] without a signed phase", peerID)
		return pending
	}
	aligned, err := phasectl.Verify(verifier, limits, messages.HashID(peerID), req.Period, *req.Signed, time.Now(), s.metrics.AlignedHeartbeat)
	if err != nil {
		log.Debugf("aligned heartbeat request from [%s] without a valid signed phase: %v", peerID, err)
		return pending
	}
	return &streamAnswer{period: period, aligned: &aligned, day: req.Signed.Day}
}

// startAlignedHeartbeat sends server heartbeats to the peer on the schedule of
// phase until ctx is done or the returned func is called. That func also
// restores the stock keepalive. A stream without an answer never gets a
// heartbeat. Sends go through Peer.Send, so they never race forwarded messages.
func (s *Server) startAlignedHeartbeat(ctx context.Context, p *peer.Peer, phase *streamPhase) func() {
	if phase == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	// The stream may start stock and switch later, so the keepalive follows the
	// schedule rather than the answer.
	ka := keepalive.ForStream(ctx)
	go phase.run(ctx, func(sched alignedhb.Answer) {
		if err := p.Send(heartbeatMessage(p.Id, sched)); err != nil {
			log.Debugf("signal heartbeat to [%s] failed: %v", p.Id, err)
			return
		}
		s.metrics.AlignedHeartbeat.HeartbeatSent(ctx)
		log.Tracef("sent signal heartbeat to [%s]", p.Id)
	}, func(sched alignedhb.Answer) {
		ka.SetAligned(sched.Period)
	})
	return func() {
		cancel()
		ka.Restore()
	}
}

// stripServerFields returns msg without the server heartbeat and the phase
// request. Only the server writes a heartbeat, and a phase request is meant for
// the server, so neither may reach a peer: a forged heartbeat would count as a
// Signal heartbeat on the victim, and a forged going-away would make it
// reconnect. msg itself is not changed.
func stripServerFields(msg *proto.EncryptedMessage) *proto.EncryptedMessage {
	if msg.GetServerHeartbeat() == nil && msg.GetPhaseRequest() == nil {
		return msg
	}
	log.Debugf("dropping server heartbeat and phase request fields from peer [%s] to peer [%s]", msg.GetKey(), msg.GetRemoteKey())
	out := gproto.Clone(msg).(*proto.EncryptedMessage)
	out.ServerHeartbeat = nil
	out.PhaseRequest = nil
	return out
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
	msg = stripServerFields(msg)
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

func (s *Server) loadPeriodLimits() alignedhb.PeriodLimits {
	if l := s.periodLimits.Load(); l != nil {
		return *l
	}
	return alignedhb.DefaultPeriodLimits()
}

// registrationHeader returns the header that confirms the registration, with
// the aligned heartbeat answer added when there is one.
func (s *Server) registrationHeader(answer *streamAnswer) metadata.MD {
	if answer == nil {
		return s.successHeader
	}
	return metadata.Join(s.successHeader, metadata.Pairs(alignedhb.MetadataKey, answer.value()))
}

// heartbeatMessage returns the server heartbeat for a peer. It has no sender key
// and no body, so it never looks like a message from another peer.
func heartbeatMessage(peerID string, sched alignedhb.Answer) *proto.EncryptedMessage {
	return &proto.EncryptedMessage{
		RemoteKey:       peerID,
		ServerHeartbeat: &proto.ServerHeartbeat{PhaseMillis: uint32(sched.Phase.Milliseconds())},
	}
}

// goingAwayMessage returns the going-away notice for a peer. It is a server
// heartbeat with the going-away flag, so stripServerFields keeps peers from
// forging it, and clients act on it only on an aligned stream.
func goingAwayMessage(peerID string) *proto.EncryptedMessage {
	return &proto.EncryptedMessage{
		RemoteKey:       peerID,
		ServerHeartbeat: &proto.ServerHeartbeat{GoingAway: true},
	}
}
