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
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/management/client"
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
)

// errReceiveStreamStalled is reported when the receive stream is transport-alive
// but no longer delivering messages, so the stream is torn down to reconnect.
var errReceiveStreamStalled = errors.New("signal receive stream stalled")

// ConnStateNotifier is a wrapper interface of the status recorder
type ConnStateNotifier interface {
	MarkSignalDisconnected(error)
	MarkSignalConnected()
}

// GrpcClient Wraps the Signal Exchange Service gRpc client
type GrpcClient struct {
	key        wgtypes.Key
	realClient proto.SignalExchangeClient
	signalConn *grpc.ClientConn
	ctx        context.Context
	stream     proto.SignalExchange_ConnectStreamClient
	// connectedCh used to notify goroutines waiting for the connection to the Signal stream
	connectedCh chan struct{}
	mux         sync.Mutex
	// StreamConnected indicates whether this client is StreamConnected to the Signal stream
	status Status

	connStateCallback     ConnStateNotifier
	connStateCallbackLock sync.RWMutex

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
}

// NewClient creates a new Signal client
func NewClient(ctx context.Context, addr string, key wgtypes.Key, tlsEnabled bool) (*GrpcClient, error) {
	var conn *grpc.ClientConn

	operation := func() error {
		var err error
		conn, err = nbgrpc.CreateConnection(ctx, addr, tlsEnabled, wsproxy.SignalComponent)
		if err != nil {
			return fmt.Errorf("create connection: %w", err)
		}
		return nil
	}

	err := backoff.Retry(operation, nbgrpc.Backoff(ctx))
	if err != nil {
		log.Errorf("failed to connect to the signalling server: %v", err)
		return nil, err
	}

	log.Debugf("connected to Signal Service: %v", conn.Target())

	return &GrpcClient{
		realClient:            proto.NewSignalExchangeClient(conn),
		ctx:                   ctx,
		signalConn:            conn,
		key:                   key,
		mux:                   sync.Mutex{},
		status:                StreamDisconnected,
		connStateCallbackLock: sync.RWMutex{},
	}, nil
}

func (c *GrpcClient) StreamConnected() bool {
	return c.status == StreamConnected
}

func (c *GrpcClient) GetStatus() Status {
	return c.status
}

// Close Closes underlying connections to the Signal Exchange
func (c *GrpcClient) Close() error {
	if c.decryptionWorkerCancel != nil {
		c.decryptionWorkerCancel()
	}
	c.decryptionWg.Wait()
	c.decryptionWorker = nil

	return c.signalConn.Close()
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

// Receive Connects to the Signal Exchange message stream and starts receiving messages.
// The messages will be handled by msgHandler function provided.
// This function is blocking and reconnects to the Signal Exchange if errors occur (e.g. Exchange restart)
// The connection retry logic will try to reconnect for 30 min and if wasn't successful will propagate the error to the function caller.
func (c *GrpcClient) Receive(ctx context.Context, msgHandler func(msg *proto.Message) error) error {

	var backOff = defaultBackoff(ctx)

	operation := func() error {

		c.notifyStreamDisconnected()

		log.Debugf("signal connection state %v", c.signalConn.GetState())
		connState := c.signalConn.GetState()
		if connState == connectivity.Shutdown {
			return backoff.Permanent(fmt.Errorf("connection to signal has been shut down"))
		} else if !(connState == connectivity.Ready || connState == connectivity.Idle) {
			c.signalConn.WaitForStateChange(ctx, connState)
			return fmt.Errorf("connection to signal is not ready and in %s state", connState)
		}

		// connect to Signal stream identifying ourselves with a public WireGuard key
		// todo once the key rotation logic has been implemented, consider changing to some other identifier (received from management)
		streamCtx, cancelStream := context.WithCancel(ctx)
		defer cancelStream()
		stream, err := c.connect(streamCtx, c.key.PublicKey().String())
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
		go c.watchReceiveStream(streamCtx, cancelStream)

		// start receiving messages from the Signal stream (from other peers through signal)
		err = c.receive(stream)
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

	err := backoff.Retry(operation, backOff)
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
	defer c.mux.Unlock()

	c.status = StreamConnected
	if c.connectedCh != nil {
		// there are goroutines waiting on this channel -> release them
		close(c.connectedCh)
		c.connectedCh = nil
	}

	if c.onReconnectedListenerFn != nil {
		c.onReconnectedListenerFn()
	}
}

func (c *GrpcClient) connect(ctx context.Context, key string) (proto.SignalExchange_ConnectStreamClient, error) {
	c.stream = nil

	// add key fingerprint to the request header to be identified on the server side
	md := metadata.New(map[string]string{proto.HeaderId: key})
	metaCtx := metadata.NewOutgoingContext(ctx, md)
	stream, err := c.realClient.ConnectStream(metaCtx, grpc.WaitForReady(true))
	c.stream = stream
	if err != nil {
		return nil, err
	}
	// blocks
	header, err := c.stream.Header()
	if err != nil {
		return nil, err
	}
	registered := header.Get(proto.HeaderRegistered)
	if len(registered) == 0 {
		return nil, fmt.Errorf("didn't receive a registration header from the Signal server whille connecting to the streams")
	}

	return stream, nil
}

// Ready indicates whether the client is okay and Ready to be used
// for now it just checks whether gRPC connection to the service is in state Ready
func (c *GrpcClient) Ready() bool {
	return c.signalConn.GetState() == connectivity.Ready || c.signalConn.GetState() == connectivity.Idle
}

// IsHealthy reports whether the Signal connection is usable, based on the
// transport state plus the receive watchdog's verdict, and updates the status
// recorder accordingly. It does not actively probe: the watchdog
// (watchReceiveStream) owns probing the receive path and reconnecting.
func (c *GrpcClient) IsHealthy() bool {
	switch c.signalConn.GetState() {
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
	err = encryption.DecryptMessage(remoteKey, c.key, msg.GetBody(), body)
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

	encryptedBody, err := encryption.EncryptMessage(remoteKey, c.key, msg.Body)
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
		ctx, cancel := context.WithTimeout(c.ctx, attemptTimeout)

		_, err = c.realClient.Send(ctx, encryptedMessage)

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
	return c.idleSinceReceive() < receiveInactivityThreshold ||
		c.receiveHandoffBlocked.Load()
}

// watchReceiveStream guards against a receive stream that is transport-alive but
// no longer delivering messages. While the stream is idle past
// receiveInactivityThreshold it sends a self-addressed probe that the Signal
// server routes back to this client. If the probe does not round-trip within
// receiveProbeTimeout the receive direction is considered dead and cancelStream
// is called so the retry loop reconnects.
func (c *GrpcClient) watchReceiveStream(ctx context.Context, cancelStream context.CancelFunc) {
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
				if err := c.sendReceiveProbe(); err != nil {
					log.Debugf("failed to send signal receive probe: %v", err)
				}
				probeSentAt = time.Now()
			}
		}
	}
}

// sendReceiveProbe sends a self-addressed heartbeat. The Signal server routes it
// back to this client, exercising the exact receive path the watchdog guards.
func (c *GrpcClient) sendReceiveProbe() error {
	self := c.key.PublicKey().String()
	return c.Send(&proto.Message{
		Key:       self,
		RemoteKey: self,
		Body:      &proto.Body{Type: proto.Body_HEARTBEAT},
	})
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

		if msg == nil {
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
