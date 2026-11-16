package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/netevents"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/util/wsproxy"
)

const (
	// receiveInactivityThreshold is how long the receive stream may be silent
	// before the watchdog actively probes it. The gRPC transport can stay
	// healthy (keepalive satisfied) while the server stops delivering messages,
	// which the transport layer cannot detect.
	receiveInactivityThreshold = 30 * time.Second
	// receiveProbeTimeout is how long the watchdog waits for its self-addressed
	// probe to round-trip back on the stream before declaring the receive
	// direction dead.
	receiveProbeTimeout = 10 * time.Second
	// receiveWatchdogInterval is how often the watchdog evaluates the stream.
	receiveWatchdogInterval = 10 * time.Second
	// defaultRegistrationTimeout bounds the wait for a new stream's registration header.
	defaultRegistrationTimeout = 10 * time.Second
	// defaultRegistrationProbeInterval is how often a new stream sends a
	// self-addressed heartbeat while it waits for its registration header.
	// Proxies such as AWS ALB withhold gRPC response headers until the first
	// message. The heartbeat is repeated because one that reaches the server
	// before the stream is registered is dropped, and spaced so a stream that
	// waits out defaultRegistrationTimeout sends at most three.
	defaultRegistrationProbeInterval = 3 * time.Second
)

// errReceiveStreamStalled is reported when the receive stream is transport-alive
// but no longer delivering messages, so the stream is torn down to reconnect.
var errReceiveStreamStalled = errors.New("signal receive stream stalled")

// errServerGoingAway is returned by receive when the server announced shutdown.
var errServerGoingAway = errors.New("signal server going away")

// streamProbeSender is the send side of the ConnectStream.
type streamProbeSender interface {
	Send(*proto.EncryptedMessage) error
}

// ConnStateNotifier is a wrapper interface of the status recorder
type ConnStateNotifier interface {
	MarkSignalDisconnected(error)
	MarkSignalConnected()
}

// GrpcClient Wraps the Signal Exchange Service gRpc client
type GrpcClient struct {
	key        wgtypes.Key
	sharedKeys *encryption.SharedKeyCache
	// conn is the connection, replaced by a redial after a stock answer.
	conn nbgrpc.RedialConn[proto.SignalExchangeClient]
	// addr is the server address, the key of its stock mark.
	addr string
	// dial creates a connection with the keepalive the stock marks give.
	dial   nbgrpc.ConnDial
	ctx    context.Context
	stream proto.SignalExchange_ConnectStreamClient
	// connectedCh used to notify goroutines waiting for the connection to the Signal stream
	connectedCh chan struct{}
	mux         sync.Mutex
	// StreamConnected indicates whether this client is StreamConnected to the Signal stream
	status Status

	connStateCallback     ConnStateNotifier
	connStateCallbackLock sync.RWMutex

	// netMgr gates the Receive retry loop on OS-reported network
	// availability and sweeps the transport on network change.
	netMgr *netevents.Manager

	onReconnectedListenerFn func()

	decryptionWorker       *Worker
	decryptionWorkerCancel context.CancelFunc
	decryptionWg           sync.WaitGroup

	// lastReceived holds the Unix-nano timestamp of the last message read from
	// the receive stream, used by the receive watchdog.
	lastReceived atomic.Int64
	// receiveStalled is set by the receive watchdog when the stream is
	// transport-alive but no longer delivering messages. It is the source of
	// truth IsHealthy reads, and is cleared once any frame is received again.
	receiveStalled atomic.Bool
	// receiveHandoffBlocked is set while the receive loop is parked handing a
	// message to a busy decryption worker. The loop stops calling Recv (and
	// markReceived) in that window, so the stream looks silent though it is
	// healthy. The watchdog reads this to avoid misreading self-inflicted
	// receive backpressure as a dead stream: reconnecting cannot help, since the
	// new stream feeds the same worker, and only triggers a reconnect storm.
	receiveHandoffBlocked atomic.Bool
	// streamProbeInflight keeps stream probe sends of the watchdog from
	// overlapping on one stream.
	streamProbeInflight atomic.Bool
	watchdogWg          sync.WaitGroup

	registrationTimeout       time.Duration
	registrationProbeInterval time.Duration

	// alignedAnswer is the aligned heartbeat the server confirmed on the current
	// stream, nil without an answer. Set it with setAlignedAnswer.
	alignedAnswer atomic.Pointer[alignedhb.Answer]
	// tcpKeepAlive follows the TCP keepalive of the connection to the answer.
	tcpKeepAlive nbgrpc.TCPKeepAlive
	// phase is the phase request writer of the current stream, nil when the
	// server sent no aligned heartbeat answer and so may not read the stream.
	phase atomic.Pointer[phaseWriter]
	// newStockMark is set when the stock answer of the current stream marked
	// the server stock anew. Only such a stream reopens on an aligned
	// Management answer, so a server that stays stock gets one reopen.
	newStockMark atomic.Bool
	// streamSendMu serializes writes on the ConnectStream, which gRPC forbids
	// from more than one goroutine at a time.
	streamSendMu sync.Mutex
}

// alignedRequest returns the aligned heartbeat period this client asks for. A
// var so tests can turn the request on outside mobile builds.
var alignedRequest = alignedhb.ClientPeriod

// Option configures optional GrpcClient behavior.
type Option func(*GrpcClient)

// WithNetEvents injects the OS network event handling.
func WithNetEvents(events *netevents.Manager) Option {
	return func(c *GrpcClient) { c.netMgr = events }
}

// NewClient creates a new Signal client
func NewClient(ctx context.Context, addr string, key wgtypes.Key, tlsEnabled bool, opts ...Option) (*GrpcClient, error) {
	// Options apply before dialing: the sweeper must wrap the first connection too.
	c := &GrpcClient{
		ctx:                       ctx,
		addr:                      addr,
		key:                       key,
		sharedKeys:                encryption.NewSharedKeyCache(key),
		mux:                       sync.Mutex{},
		status:                    StreamDisconnected,
		connStateCallbackLock:     sync.RWMutex{},
		registrationTimeout:       defaultRegistrationTimeout,
		registrationProbeInterval: defaultRegistrationProbeInterval,
	}
	for _, opt := range opts {
		opt(c)
	}

	var sweeper nbgrpc.Sweeper
	if c.netMgr != nil {
		sweeper = c.netMgr
	}
	// Signal dials are never held: the Signal stream carries the heartbeat
	// burst the Management retries wait for.
	extraOpts := []grpc.DialOption{nbgrpc.WithDialHooks(sweeper, &c.tcpKeepAlive, nil)}

	c.dial = nbgrpc.NewConnDial(wsproxy.SignalComponent, addr, tlsEnabled, hbwatch.WaitSignalConnect, logStockDial, extraOpts...)

	conn, ka, err := c.dial(ctx)
	if err != nil {
		log.Errorf("failed to connect to the signalling server: %v", err)
		return nil, err
	}

	log.Debugf("connected to Signal Service: %v", conn.Target())

	c.conn.Swap(conn, proto.NewSignalExchangeClient(conn), ka)
	return c, nil
}

// logStockDial notes a dial with the stock keepalive after a stock answer.
func logStockDial(ka time.Duration) {
	_, asked := alignedRequest()
	nbgrpc.LogStockDial("Signal", asked, ka)
}

// stockAnswer marks the server stock for this session and redials a connection
// with the aligned keepalive. It reports whether the mark is new.
func (c *GrpcClient) stockAnswer() bool {
	return c.conn.StockAnswer(c.ctx, nbgrpc.Redialer[proto.SignalExchangeClient]{
		Name:      "Signal",
		Component: wsproxy.SignalComponent,
		Addr:      c.addr,
		Dial:      c.dial,
		NewClient: proto.NewSignalExchangeClient,
	})
}

// answeredStock reports whether the current stream asked for the aligned
// heartbeat and the server sent no answer to it.
func (c *GrpcClient) answeredStock() bool {
	_, asked := alignedRequest()
	return asked && c.phase.Load() == nil
}

// reopensOnAlignedAnswer reports whether the current stream reopens on an
// aligned Management answer: it answered stock and marked the server stock
// anew. A stream that finds the mark set, as after such a reopen landed on a
// server that is still stock, stays until the server answers aligned once.
func (c *GrpcClient) reopensOnAlignedAnswer() bool {
	return c.answeredStock() && c.newStockMark.Load()
}

// reopenOnAlignedAnswer cancels a stream the server opened stock when
// Management answers aligned, so the stream reopens with the signed phase. A
// stock stream behind a proxy can outlive the stock server it opened on, and
// only the receive watchdog would drop it, minutes later.
func reopenOnAlignedAnswer(ctx context.Context, cancelStream context.CancelFunc, mgmtAligned <-chan struct{}) {
	select {
	case <-ctx.Done():
	case <-mgmtAligned:
		log.Infof("Management answered aligned while the Signal stream runs stock, reopening it")
		cancelStream()
	}
}

func (c *GrpcClient) StreamConnected() bool {
	return c.GetStatus() == StreamConnected
}

func (c *GrpcClient) GetStatus() Status {
	c.mux.Lock()
	defer c.mux.Unlock()
	return c.status
}

// Close Closes underlying connections to the Signal Exchange
func (c *GrpcClient) Close() error {
	if c.decryptionWorkerCancel != nil {
		c.decryptionWorkerCancel()
	}
	c.decryptionWg.Wait()
	c.decryptionWorker = nil
	c.sharedKeys.Close()

	return c.conn.Close()
}

// SetConnStateListener set the ConnStateNotifier
func (c *GrpcClient) SetConnStateListener(notifier ConnStateNotifier) {
	c.connStateCallbackLock.Lock()
	defer c.connStateCallbackLock.Unlock()
	c.connStateCallback = notifier
}

// defaultBackoff is a basic backoff mechanism for general issues
func defaultBackoff(ctx context.Context) backoff.BackOff {
	return backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)
}

// receiveBackoff is the backoff of the receive retry loop. A var so tests can
// use waits no timer reaches.
var receiveBackoff = defaultBackoff

// Receive Connects to the Signal Exchange message stream and starts receiving messages.
// The messages will be handled by msgHandler function provided.
// This function is blocking and reconnects to the Signal Exchange if errors occur (e.g. Exchange restart)
// The connection retry logic will try to reconnect for 30 min and if wasn't successful will propagate the error to the function caller.
func (c *GrpcClient) Receive(ctx context.Context, msgHandler func(msg *proto.Message) error) error {

	backOff := c.netMgr.QuickRetryBackoff(ctx, receiveBackoff(ctx))

	operation := func() error {
		conn := c.conn.Conn()
		// suspend reconnect attempts while the OS reports no usable network.
		// Wait only errors on a cancelled context, which means shutdown, so
		// stop the loop without reporting a failure.
		if waited, err := c.netMgr.Wait(ctx); err != nil {
			log.Debugf("signal connection context has been canceled while offline, this usually indicates shutdown")
			return nil
		} else if waited {
			backOff.Reset()
			// dials attempted while offline grew the channel's internal backoff;
			// reset it too, or the reconnect waits out that timer first
			conn.ResetConnectBackoff()
		}

		c.notifyStreamDisconnected()

		if err := c.conn.Ready(ctx, conn, "Signal"); err != nil {
			return err
		}

		// Taken before the stream opens, so an answer during the open counts.
		mgmtAligned := alignedhb.SignedAnswerAnnounced()

		// connect to Signal stream identifying ourselves with a public WireGuard key
		// todo once the key rotation logic has been implemented, consider changing to some other identifier (received from management)
		streamCtx, cancelStream := context.WithCancel(ctx)
		defer cancelStream()
		stream, err := c.connect(streamCtx, cancelStream, c.key.PublicKey().String())
		if err != nil {
			log.Warnf("disconnected from the Signal Exchange due to an error: %v", err)
			return err
		}

		c.notifyStreamConnected()

		log.Infof("connected to the Signal Service stream")
		c.notifyConnected()

		// Start worker pool if not already started
		c.startEncryptionWorker(msgHandler)

		// Guard the receive direction: the transport can stay healthy while the
		// server stops delivering messages. The watchdog reconnects via cancelStream.
		c.markReceived()
		c.watchdogWg.Add(1)
		go func() {
			defer c.watchdogWg.Done()
			c.watchReceiveStream(streamCtx, cancelStream, stream)
		}()
		if c.reopensOnAlignedAnswer() {
			c.watchdogWg.Add(1)
			go func() {
				defer c.watchdogWg.Done()
				reopenOnAlignedAnswer(streamCtx, cancelStream, mgmtAligned)
			}()
		}
		// A missed tick reconnects at once. A probe first costs a full period
		// when the phone sleeps before the answer is checked.
		reg := hbwatch.Registration{
			Kind: hbwatch.ActionReconnect,
			Addr: c.addr,
			Stale: func() {
				log.Warnf("signal stream is stale, reconnecting")
				cancelStream()
			},
		}
		if pw := c.phase.Load(); pw != nil {
			reg.Correct = pw.correct
			go pw.forwardSignedPhases(streamCtx)
		}
		if a := c.alignedAnswer.Load(); a != nil {
			reg.AlignedPeriod = a.Period
		}
		unregisterStale := hbwatch.Register(hbwatch.Signal, reg)

		// start receiving messages from the Signal stream (from other peers through signal)
		err = c.receive(stream)

		unregisterStale()
		cancelStream()
		c.watchdogWg.Wait()

		if err != nil {
			// Check the parent context, not streamCtx: a watchdog-triggered
			// cancelStream must reconnect, only a parent cancel is shutdown.
			if ctx.Err() != nil {
				log.Debugf("signal connection context has been canceled, this usually indicates shutdown")
				return nil
			}
			// we need this reset because after a successful connection and a consequent error, backoff lib doesn't
			// reset times and next try will start with a long delay
			backOff.Reset()
			c.notifyDisconnected(err)
			log.Warnf("disconnected from the Signal service but will retry silently. Reason: %v", err)
			return err
		}

		return nil
	}

	err := nbgrpc.Retry(ctx, operation, backOff, c.netMgr, hbwatch.WaitSignalReceive)
	if err != nil {
		log.Errorf("exiting the Signal service connection retry loop due to the unrecoverable error: %v", err)
		return err
	}

	return nil
}

func (c *GrpcClient) notifyStreamDisconnected() {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.status = StreamDisconnected
}

func (c *GrpcClient) notifyStreamConnected() {
	c.mux.Lock()

	c.status = StreamConnected
	if c.connectedCh != nil {
		// there are goroutines waiting on this channel -> release them
		close(c.connectedCh)
		c.connectedCh = nil
	}

	listener := c.onReconnectedListenerFn
	c.mux.Unlock()

	// Listeners can hold their own locks while unregistering from this client.
	if listener != nil {
		listener()
	}
}

func (c *GrpcClient) connect(ctx context.Context, cancel context.CancelFunc, key string) (proto.SignalExchange_ConnectStreamClient, error) {
	c.stream = nil

	// A new stream starts stock until its own answer arrives.
	c.setAlignedAnswer(nil)
	c.phase.Store(nil)
	c.newStockMark.Store(false)

	// add key fingerprint to the request header to be identified on the server side
	md := metadata.New(map[string]string{proto.HeaderId: key})
	alignedReq, sentSeq, asked := alignedStreamRequest(key)
	if asked {
		md.Set(alignedhb.MetadataKey, alignedReq.Value())
	}
	metaCtx := metadata.NewOutgoingContext(ctx, md)
	stream, err := c.conn.Client().ConnectStream(metaCtx, grpc.WaitForReady(true))
	c.stream = stream
	if err != nil {
		return nil, err
	}
	stopProbes := c.probeUntilRegistered(ctx)
	defer stopProbes()
	header, err := awaitRegistration(stream, c.registrationTimeout, cancel)
	if err != nil {
		return nil, err
	}
	if asked {
		c.applyAlignedAnswer(header, stream, key, sentSeq)
	}

	return stream, nil
}

// applyAlignedAnswer reads the aligned heartbeat answer of a new stream. Any
// answer shows that the server reads the stream, so phase requests may be
// written on it. Only an answer with a phase turns the aligned heartbeat on.
func (c *GrpcClient) applyAlignedAnswer(header metadata.MD, stream streamProbeSender, key string, sentSeq uint64) {
	answer, aligned, ok := alignedAnswerFromHeader(header)
	if !ok {
		c.newStockMark.Store(c.stockAnswer())
		return
	}
	nbgrpc.ClearStock(wsproxy.SignalComponent, c.addr)
	if aligned {
		c.setAlignedAnswer(&answer)
	}
	c.phase.Store(newPhaseWriter(stream, &c.streamSendMu, messages.HashID(key), key, answer.Period, sentSeq))
}

// alignedHeartbeat returns the aligned heartbeat the Signal server confirmed on
// the current stream. ok is false without an answer, which keeps the client stock.
func (c *GrpcClient) alignedHeartbeat() (answer alignedhb.Answer, ok bool) {
	a := c.alignedAnswer.Load()
	if a == nil {
		return alignedhb.Answer{}, false
	}
	return *a, true
}

// setAlignedAnswer records the aligned heartbeat answer of the current stream,
// nil for none, and sets the TCP keepalive of the connection to match.
func (c *GrpcClient) setAlignedAnswer(answer *alignedhb.Answer) {
	c.alignedAnswer.Store(answer)
	if answer == nil {
		c.tcpKeepAlive.SetStock()
		return
	}
	c.tcpKeepAlive.SetAligned(answer.Period)
}

// probeUntilRegistered sends a self-addressed heartbeat every
// registrationProbeInterval until the returned stop function is called. The
// server forwards it onto this client's stream, so a proxy that holds the
// registration header until the first message releases it.
func (c *GrpcClient) probeUntilRegistered(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(c.registrationProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.sendReceiveProbe(ctx); err != nil && ctx.Err() == nil {
					log.Debugf("failed to send signal registration probe: %v", err)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// alignedStreamRequest returns the aligned heartbeat request for a stream of the
// peer with public key key, and the sequence number of the signed phase in it.
// It carries the last phase Management signed, with the period it was signed
// for, once the client has one.
func alignedStreamRequest(key string) (alignedhb.StreamRequest, uint64, bool) {
	period, asked := alignedRequest()
	if !asked {
		return alignedhb.StreamRequest{}, 0, false
	}
	stored, ok := alignedhb.LoadStoredPhase(messages.HashID(key))
	if !ok {
		return alignedhb.StreamRequest{Period: period}, 0, true
	}
	return alignedhb.StreamRequest{Period: stored.Period, Signed: &stored.Signed}, stored.Seq, true
}

// alignedAnswerFromHeader returns the aligned heartbeat answer in the
// registration header. ok is false when an old server sent none or it is
// unreadable. aligned is false for an answer without a phase: the server reads
// the stream but has no valid signed phase yet.
func alignedAnswerFromHeader(header metadata.MD) (answer alignedhb.Answer, aligned, ok bool) {
	v := header.Get(alignedhb.MetadataKey)
	if len(v) == 0 {
		return alignedhb.Answer{}, false, false
	}
	answer, aligned, err := alignedhb.ParseStreamAnswer(v[0])
	if err != nil {
		log.Warnf("ignoring aligned heartbeat answer from Signal: %v", err)
		return alignedhb.Answer{}, false, false
	}
	if clamped, ok := alignedhb.ClampAnswer(answer); ok {
		log.Warnf("aligned heartbeat period %s from Signal outside %s to %s, using %s",
			answer.Period, alignedhb.MinPeriod, alignedhb.MaxPeriod, clamped.Period)
		answer = clamped
	}
	if !aligned {
		log.Infof("Signal reads the stream, period %s, waiting for a signed phase", answer.Period)
		return answer, false, true
	}
	log.Infof("aligned heartbeat on the Signal stream, period %s, phase %d ms", answer.Period, answer.Phase.Milliseconds())
	return answer, true, true
}

func awaitRegistration(stream proto.SignalExchange_ConnectStreamClient, timeout time.Duration, cancel context.CancelFunc) (metadata.MD, error) {
	// A timer rather than a context deadline: the stream context must outlive registration.
	timer := time.AfterFunc(timeout, cancel)
	header, err := stream.Header()
	if !timer.Stop() {
		return nil, fmt.Errorf("no registration header from the Signal server within %s", timeout)
	}
	if err != nil {
		return nil, err
	}
	registered := header.Get(proto.HeaderRegistered)
	if len(registered) == 0 {
		return nil, fmt.Errorf("didn't receive a registration header from the Signal server whille connecting to the streams")
	}
	return header, nil
}

// Ready indicates whether the client is okay and Ready to be used
// for now it just checks whether gRPC connection to the service is in state Ready
func (c *GrpcClient) Ready() bool {
	state := c.conn.Conn().GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// IsHealthy reports whether the Signal connection is usable, based on the
// transport state plus the receive watchdog's verdict, and updates the status
// recorder accordingly. It does not actively probe: the watchdog
// (watchReceiveStream) owns probing the receive path and reconnecting.
func (c *GrpcClient) IsHealthy() bool {
	c.mux.Lock()
	registered := c.status == StreamConnected
	c.mux.Unlock()
	if !registered {
		return false
	}

	switch c.conn.Conn().GetState() {
	case connectivity.TransientFailure:
		return false
	case connectivity.Connecting:
		return true
	case connectivity.Shutdown:
		return true
	case connectivity.Idle:
	case connectivity.Ready:
	}

	if c.receiveStalled.Load() {
		c.notifyDisconnected(errReceiveStreamStalled)
		return false
	}
	c.notifyConnected()
	return true
}

// WaitStreamConnected waits until the client is connected to the Signal stream
func (c *GrpcClient) WaitStreamConnected(ctx context.Context) {
	// Check the status and obtain the wait channel atomically: otherwise
	// notifyStreamConnected could flip the status and close/clear the channel
	// between the check and the channel creation, leaving us waiting forever on
	// a stale channel.
	c.mux.Lock()
	if c.status == StreamConnected {
		c.mux.Unlock()
		return
	}
	if c.connectedCh == nil {
		c.connectedCh = make(chan struct{})
	}
	ch := c.connectedCh
	c.mux.Unlock()

	select {
	case <-ctx.Done():
	case <-c.ctx.Done():
	case <-ch:
	}
}

// SetOnReconnectedListener replaces the listener without waiting for an in-flight callback.
func (c *GrpcClient) SetOnReconnectedListener(fn func()) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.onReconnectedListenerFn = fn
}

// SendToStream sends a message to the remote Peer through the Signal Exchange using established stream connection to the Signal Server
// The GrpcClient.Receive method must be called before sending messages to establish initial connection to the Signal Exchange
// GrpcClient.connWg can be used to wait
func (c *GrpcClient) SendToStream(msg *proto.EncryptedMessage) error {
	if !c.Ready() {
		return fmt.Errorf("no connection to signal")
	}
	if c.stream == nil {
		return fmt.Errorf("connection to the Signal Exchange has not been established yet. Please call GrpcClient.Receive before sending messages")
	}

	err := c.stream.Send(msg)
	if err != nil {
		log.Errorf("error while sending message to peer [%s] [error: %v]", msg.RemoteKey, err)
		return err
	}

	return nil
}

// decryptMessage decrypts the body of the msg using Wireguard private key and Remote peer's public key
func (c *GrpcClient) decryptMessage(msg *proto.EncryptedMessage) (*proto.Message, error) {
	remoteKey, err := wgtypes.ParseKey(msg.GetKey())
	if err != nil {
		return nil, err
	}

	body := &proto.Body{}
	err = c.sharedKeys.DecryptMessage(remoteKey, msg.GetBody(), body)
	if err != nil {
		return nil, err
	}

	return &proto.Message{
		Key:       msg.Key,
		RemoteKey: msg.RemoteKey,
		Body:      body,
	}, nil
}

// encryptMessage encrypts the body of the msg using Wireguard private key and Remote peer's public key
func (c *GrpcClient) encryptMessage(msg *proto.Message) (*proto.EncryptedMessage, error) {

	remoteKey, err := wgtypes.ParseKey(msg.RemoteKey)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := c.sharedKeys.EncryptMessage(remoteKey, msg.Body)
	if err != nil {
		return nil, err
	}

	return &proto.EncryptedMessage{
		Key:       msg.GetKey(),
		RemoteKey: msg.GetRemoteKey(),
		Body:      encryptedBody,
	}, nil
}

// Send sends a message to the remote Peer through the Signal Exchange.
func (c *GrpcClient) Send(msg *proto.Message) error {
	return c.send(c.ctx, msg)
}

// send delivers a message deriving per-attempt timeouts from parentCtx, so a
// caller can abort an in-flight send by cancelling that context.
func (c *GrpcClient) send(parentCtx context.Context, msg *proto.Message) error {
	if !c.Ready() {
		return fmt.Errorf("no connection to signal")
	}

	encryptedMessage, err := c.encryptMessage(msg)
	if err != nil {
		return err
	}

	attemptTimeout := client.ConnectTimeout

	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 1 {
			attemptTimeout = time.Duration(attempt) * 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(parentCtx, attemptTimeout)

		_, err = c.conn.Client().Send(ctx, encryptedMessage)

		cancel()

		if s, ok := status.FromError(err); ok && s.Code() == codes.Canceled {
			return err
		}

		if err == nil {
			return nil
		}
	}

	return err
}

// markReceived records that a frame was just read from the receive stream and
// clears the stalled flag.
func (c *GrpcClient) markReceived() {
	c.lastReceived.Store(time.Now().UnixNano())
	c.receiveStalled.Store(false)
}

// idleSinceReceive returns how long the receive stream has been silent.
func (c *GrpcClient) idleSinceReceive() time.Duration {
	return time.Since(time.Unix(0, c.lastReceived.Load()))
}

// receiveAlive reports whether the receive stream shows liveness: it delivered a
// frame within the inactivity threshold, or the receive loop is currently parked
// handing a message to a busy decryption worker. In the latter case the loop has
// stopped calling Recv, so the stream looks silent while being healthy, and
// reconnecting would not help, so the watchdog must treat it as alive.
func (c *GrpcClient) receiveAlive() bool {
	return c.idleSinceReceive() < c.inactivityThreshold() || c.receiveHandoffBlocked.Load()
}

// inactivityThreshold returns how long the stream may be silent before the
// watchdog probes it. An aligned stream is silent for a whole period between
// heartbeats, so it gets the receive timeout of its period.
func (c *GrpcClient) inactivityThreshold() time.Duration {
	if a := c.alignedAnswer.Load(); a != nil {
		return alignedhb.ReceiveTimeout(a.Period)
	}
	return receiveInactivityThreshold
}

// watchReceiveStream guards against a receive stream that is transport-alive but
// no longer delivering messages. While the stream is idle past
// receiveInactivityThreshold it sends a self-addressed probe that the Signal
// server routes back to this client. If the probe does not round-trip within
// receiveProbeTimeout the receive direction is considered dead and cancelStream
// is called so the retry loop reconnects.
func (c *GrpcClient) watchReceiveStream(ctx context.Context, cancelStream context.CancelFunc, stream streamProbeSender) {
	ticker := time.NewTicker(receiveWatchdogInterval)
	defer ticker.Stop()

	var probeSentAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.receiveAlive() {
				probeSentAt = time.Time{}
				continue
			}

			if !probeSentAt.IsZero() && time.Since(probeSentAt) >= receiveProbeTimeout {
				log.Warnf("signal receive stream stalled: no messages for %s and probe did not return, reconnecting", c.idleSinceReceive().Round(time.Second))
				c.receiveStalled.Store(true)
				c.notifyDisconnected(errReceiveStreamStalled)
				cancelStream()
				return
			}

			if probeSentAt.IsZero() {
				c.sendStreamProbe(stream, &c.streamProbeInflight)
				if err := c.sendReceiveProbe(ctx); err != nil {
					log.Debugf("failed to send signal receive probe: %v", err)
				}
				probeSentAt = time.Now()
			}
		}
	}
}

// sendReceiveProbe sends a self-addressed heartbeat bound to ctx, so cancelStream
// aborts an in-flight probe instead of leaving the watchdog blocked on send timeouts.
// The Signal server routes it back to this client, exercising the exact receive
// path the watchdog guards.
func (c *GrpcClient) sendReceiveProbe(ctx context.Context) error {
	self := c.key.PublicKey().String()
	return c.send(ctx, &proto.Message{
		Key:       self,
		RemoteKey: self,
		Body:      &proto.Body{Type: proto.Body_HEARTBEAT},
	})
}

// sendStreamProbe writes one frame on the ConnectStream itself. A Go reverse
// proxy whose backend stream already ended holds the client stream open until
// the client writes on it, so this write lets the proxy end it. The send runs in
// its own goroutine because it can block on flow control until cancelStream.
// inflight keeps sends on one stream from overlapping, which gRPC forbids.
// The server drops stream frames without a phase request, so the frame needs no
// marker. Only a server that answered the aligned heartbeat request reads the
// stream: on an old server the writes would fill the flow control window, so
// nothing is written there.
func (c *GrpcClient) sendStreamProbe(stream streamProbeSender, inflight *atomic.Bool) {
	if c.phase.Load() == nil {
		return
	}
	if !inflight.CompareAndSwap(false, true) {
		return
	}
	self := c.key.PublicKey().String()
	go func() {
		defer inflight.Store(false)
		c.streamSendMu.Lock()
		defer c.streamSendMu.Unlock()
		if err := stream.Send(&proto.EncryptedMessage{Key: self, RemoteKey: self}); err != nil {
			log.Debugf("failed to send signal stream probe: %v", err)
		}
	}()
}

// receive receives messages from other peers coming through the Signal Exchange
// and distributes them to worker threads for processing
func (c *GrpcClient) receive(stream proto.SignalExchange_ConnectStreamClient) error {
	for {
		msg, err := stream.Recv()
		// Handle errors immediately
		switch s, ok := status.FromError(err); {
		case ok && s.Code() == codes.Canceled:
			log.Debugf("stream canceled (usually indicates shutdown)")
			return err
		case s.Code() == codes.Unavailable:
			log.Debugf("Signal Service is unavailable")
			return err
		case err == io.EOF:
			log.Debugf("Signal Service stream closed by server")
			return err
		case err != nil:
			log.Errorf("Stream receive error: %v", err)
			return err
		}

		// Any frame from the server proves the receive direction is alive.
		c.markReceived()
		hb := c.serverHeartbeat(msg)
		// Going-away rides in a server heartbeat, so the same gate decides: only
		// the server of an aligned stream can send it. It carries no phase.
		if hb.GetGoingAway() {
			log.Infof("signal server going away, reconnecting")
			return errServerGoingAway
		}
		if hb != nil {
			c.seenHeartbeat(hb)
		} else {
			hbwatch.Touch(hbwatch.Signal)
		}

		if msg == nil {
			continue
		}

		// A server heartbeat is not end to end encrypted and has no body, so it
		// never goes to the decryption worker, forged or not.
		if msg.GetServerHeartbeat() != nil {
			if hb == nil {
				log.Debugf("ignoring signal heartbeat from [%s]: not written by the server of an aligned stream", msg.GetKey())
				continue
			}
			log.Tracef("received signal heartbeat, phase %d ms", hb.GetPhaseMillis())
			continue
		}

		// The handoff blocks while the worker is busy, which parks this loop and
		// stops Recv. Flag it so the watchdog does not read the resulting silence
		// as a dead stream.
		c.receiveHandoffBlocked.Store(true)
		if err := c.decryptionWorker.AddMsg(c.ctx, msg); err != nil {
			log.Errorf("failed to add message to decryption worker: %v", err)
		}
		// Refresh liveness before clearing the flag so the window between here and
		// the next Recv does not read a stale timestamp as a dead stream.
		c.markReceived()
		c.receiveHandoffBlocked.Store(false)
	}
}

func (c *GrpcClient) startEncryptionWorker(handler func(msg *proto.Message) error) {
	if c.decryptionWorker != nil {
		return
	}

	c.decryptionWorker = NewWorker(c.decryptMessage, handler)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	c.decryptionWorkerCancel = workerCancel

	c.decryptionWg.Add(1)
	go func() {
		defer workerCancel()
		c.decryptionWorker.Work(workerCtx)
		c.decryptionWg.Done()
	}()
}

func (c *GrpcClient) notifyDisconnected(err error) {
	c.connStateCallbackLock.RLock()
	defer c.connStateCallbackLock.RUnlock()

	if c.connStateCallback == nil {
		return
	}
	c.connStateCallback.MarkSignalDisconnected(err)
}

func (c *GrpcClient) notifyConnected() {
	c.connStateCallbackLock.RLock()
	defer c.connStateCallbackLock.RUnlock()

	if c.connStateCallback == nil {
		return
	}
	c.connStateCallback.MarkSignalConnected()
}
