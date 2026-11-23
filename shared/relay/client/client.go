package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/netevents/sweep"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	bufferSize            = 8820
	serverResponseTimeout = 8 * time.Second
	connChannelSize       = 100
)

var (
	ErrConnAlreadyExists = fmt.Errorf("connection already exists")
	// ErrServerDisconnected is the cancellation cause of a relayed Conn when the
	// client lost the connection to the relay server.
	ErrServerDisconnected = fmt.Errorf("relay server disconnected")
	// ErrPeerDisconnected is the cancellation cause of a relayed Conn when the
	// remote peer went offline.
	ErrPeerDisconnected = fmt.Errorf("remote peer disconnected")
)

type internalStopFlag struct {
	sync.Mutex
	stop bool
}

func newInternalStopFlag() *internalStopFlag {
	return &internalStopFlag{}
}

func (isf *internalStopFlag) set() {
	isf.Lock()
	defer isf.Unlock()
	isf.stop = true
}

func (isf *internalStopFlag) isSet() bool {
	isf.Lock()
	defer isf.Unlock()
	return isf.stop
}

// Msg carry the payload from the server to the client. With this struct, the net.Conn can free the buffer.
type Msg struct {
	Payload []byte

	bufPool *sync.Pool
	bufPtr  *[]byte
}

func (m *Msg) Free() {
	m.bufPool.Put(m.bufPtr)
}

// connContainer is a container for the connection to the peer. It is responsible for managing the messages from the
// server and forwarding them to the upper layer content reader.
type connContainer struct {
	log         *log.Entry
	conn        *Conn
	messages    chan Msg
	msgChanLock sync.Mutex
	closed      bool // flag to check if channel is closed
	ctx         context.Context
	cancel      context.CancelCauseFunc
}

func newConnContainer(log *log.Entry, c *Client, peerID messages.PeerID, instanceURL *RelayAddr) *connContainer {
	ctx, cancel := context.WithCancelCause(context.Background())
	msgChan := make(chan Msg, connChannelSize)
	cn := &Conn{
		dstID:       peerID,
		messageChan: msgChan,
		instanceURL: instanceURL,
		ctx:         ctx,
	}
	cc := &connContainer{
		log:      log,
		conn:     cn,
		messages: msgChan,
		ctx:      ctx,
		cancel:   cancel,
	}

	// bind conn to client
	cn.writeFn = func(dstID messages.PeerID, payload []byte) (int, error) {
		return c.writeTo(cc, dstID, payload)
	}
	cn.closeFn = func(dstID messages.PeerID) error {
		return c.closeConn(cc, dstID)
	}
	cn.localAddrFn = func() net.Addr {
		return c.relayConn.LocalAddr()
	}
	return cc
}

func (cc *connContainer) writeMsg(msg Msg) {
	cc.msgChanLock.Lock()
	defer cc.msgChanLock.Unlock()

	if cc.closed {
		msg.Free()
		return
	}

	select {
	case cc.messages <- msg:
	case <-cc.ctx.Done():
		msg.Free()
	default:
		msg.Free()
	}
}

func (cc *connContainer) close(cause error) {
	cc.cancel(cause)

	cc.msgChanLock.Lock()
	defer cc.msgChanLock.Unlock()

	if cc.closed {
		return
	}

	cc.closed = true
	close(cc.messages)

	for msg := range cc.messages {
		msg.Free()
	}
}

// transportConn is implemented by relay connections that know their transport.
type transportConn interface {
	Protocol() string
}

type sizedConn interface {
	MaxMessageSize() int
}

// NetEvents is the OS network event view the relay consumes: availability
// gating for the reconnect guard and dial registration for the network change
// sweep.
type NetEvents interface {
	NetworkWatcher
	StartDial(ctx context.Context) *sweep.Dial
}

// Client is a client for the relay server. It is responsible for establishing a connection to the relay server and
// managing connections to other peers. All exported functions are safe to call concurrently. After close the connection,
// the client can be reused by calling Connect again. When the client is closed, all connections are closed too.
// While the Connect is in progress, the OpenConn function will block until the connection is established with relay server.
type Client struct {
	log            *log.Entry
	connectionURL  string
	serverIP       netip.Addr
	authTokenStore *auth.TokenStore
	hashedID       messages.PeerID

	bufPool *sync.Pool

	relayConn        net.Conn
	conns            map[messages.PeerID]*connContainer
	earlyMsgs        *earlyMsgBuffer
	serviceIsRunning bool
	mu               sync.Mutex // protect serviceIsRunning and conns
	readLoopMutex    sync.Mutex
	wgReadLoop       sync.WaitGroup
	instanceURL      *RelayAddr
	muInstanceURL    sync.Mutex

	onDisconnectListener func(string)
	listenerMutex        sync.Mutex

	stateSubscription *PeersStateSubscription

	mtu uint16

	// transportFallback, when set, records datagram-too-large failures so a
	// datagram-sized transport is avoided on subsequent connects. Shared via
	// the manager.
	transportFallback *transportFallback

	// netEvents registers the relay dial for the network change sweep; the
	// read loop reports the disconnect and the guard reconnects. Shared via
	// the manager.
	netEvents NetEvents
	// datagramFallbackTriggered guards a single fallback per connection so a
	// burst of oversized datagrams triggers one reconnect, not many.
	datagramFallbackTriggered atomic.Bool

	// transport is the negotiated relay transport of the
	// current connection, guarded by mu.
	transport string

	maxMsgSize int

	// alignedPeriod is the heartbeat period the server confirmed on the
	// current connection in nanoseconds, zero while stock. Connect and the
	// read loop of the current connection write it under watchMu, status
	// reads it atomically.
	alignedPeriod atomic.Int64
	// alignedRequest returns the aligned heartbeat period to ask for, ok
	// false for none.
	alignedRequest func() (period time.Duration, ok bool)
	// watch marks the home relay client: only it registers with hbwatch.
	watch atomic.Bool
	// watchMu guards watchStop, watchSeq and watchGen. watchSeq counts
	// the Connect calls and watchGen is the sequence the current
	// registration belongs to: the read loop of an old connection must
	// not unregister a newer one.
	watchMu   sync.Mutex
	watchStop func()
	watchSeq  int
	watchGen  int
	// stopFlag is the flag listenForStopEvents sets on a timeout close of
	// the current connection. Guarded by mu.
	stopFlag *internalStopFlag
}

// Transport returns the negotiated relay transport of the current connection,
// or an empty string when not connected.
func (c *Client) Transport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transport
}

// SetTransportFallback wires the shared datagram-transport fallback tracker.
func (c *Client) SetTransportFallback(tf *transportFallback) {
	c.transportFallback = tf
}

// WatchHeartbeats marks this client as the home relay client: it registers
// with hbwatch on every Connect, and at once when already connected. The
// manager calls it only for the home client, so foreign relay connections
// are never watched. It is idempotent.
func (c *Client) WatchHeartbeats() {
	c.watch.Store(true)
	c.mu.Lock()
	running := c.serviceIsRunning
	relayConn := c.relayConn
	stopFlag := c.stopFlag
	c.mu.Unlock()
	if !running {
		return
	}
	c.watchMu.Lock()
	seq := c.watchSeq
	c.watchMu.Unlock()
	c.startWatch(seq, relayConn, stopFlag)
}

// AlignedPeriod returns the heartbeat period the server confirmed on the
// current connection, zero while stock.
func (c *Client) AlignedPeriod() time.Duration {
	return time.Duration(c.alignedPeriod.Load())
}

// startWatch registers the connection of sequence seq with hbwatch, unless
// a registration is already in place. Its stale action closes relayConn
// like a health check timeout, with stopFlag the flag of that connection.
// It takes only watchMu, so Connect can call it while it holds c.mu.
func (c *Client) startWatch(seq int, relayConn net.Conn, stopFlag *internalStopFlag) {
	if !c.watch.Load() {
		return
	}
	c.watchMu.Lock()
	if c.watchStop != nil {
		c.watchMu.Unlock()
		return
	}
	c.watchMu.Unlock()

	reconnect := func() {
		c.log.Warnf("relay connection is stale, closing it like a health check timeout")
		if stopFlag != nil {
			stopFlag.set()
		}
		if err := relayConn.Close(); err != nil {
			c.log.Debugf("failed to close stale relay connection: %s", err)
		}
	}
	stop := hbwatch.Register(hbwatch.Relay, hbwatch.Registration{
		Kind:  hbwatch.ActionReconnect,
		Stale: reconnect,
		Addr:  c.connectionURL,
	})
	c.watchMu.Lock()
	if c.watchStop == nil && c.watchSeq == seq {
		c.watchStop = stop
		c.watchGen = seq
		c.watchMu.Unlock()
		return
	}
	c.watchMu.Unlock()
	stop()
}

// clearWatchGen unregisters the registration of connection sequence seq,
// and only that one.
func (c *Client) clearWatchGen(seq int) {
	c.watchMu.Lock()
	if c.watchGen != seq || c.watchStop == nil {
		c.watchMu.Unlock()
		return
	}
	stop := c.watchStop
	c.watchStop = nil
	c.watchMu.Unlock()
	stop()
}

// NewClient creates a new client for the relay server. The client is not connected to the server until the Connect
// is called.
func NewClient(serverURL string, authTokenStore *auth.TokenStore, peerID string, mtu uint16) *Client {
	return NewClientWithServerIP(serverURL, netip.Addr{}, authTokenStore, peerID, mtu)
}

// NewClientWithServerIP creates a new client for the relay server with a known server IP. serverIP, when valid, is
// dialed directly first; the FQDN is only attempted if the IP-based dial fails. TLS verification still uses the
// FQDN from serverURL via SNI.
func NewClientWithServerIP(serverURL string, serverIP netip.Addr, authTokenStore *auth.TokenStore, peerID string, mtu uint16) *Client {
	hashedID := messages.HashID(peerID)
	relayLog := log.WithFields(log.Fields{"relay": serverURL})

	c := &Client{
		log:            relayLog,
		connectionURL:  serverURL,
		serverIP:       serverIP,
		authTokenStore: authTokenStore,
		hashedID:       hashedID,
		mtu:            mtu,
		bufPool: &sync.Pool{
			New: func() any {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
		conns:          make(map[messages.PeerID]*connContainer),
		alignedRequest: alignedhb.ClientPeriod,
	}

	c.earlyMsgs = newEarlyMsgBuffer()

	c.log.Infof("create new relay connection: local peerID: %s, local peer hashedID: %s", peerID, hashedID)
	return c
}

// Connect establishes a connection to the relay server. It blocks until the connection is established or an error occurs.
func (c *Client) Connect(ctx context.Context) error {
	c.log.Infof("connecting to relay server")
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.serviceIsRunning {
		return nil
	}

	instanceURL, err := c.connect(ctx)
	if err != nil {
		return err
	}
	c.muInstanceURL.Lock()
	c.instanceURL = instanceURL
	c.muInstanceURL.Unlock()

	c.stateSubscription = NewPeersStateSubscription(c.log, c.relayConn, c.maxMsgSize, c.closeConnsByPeerID)

	c.log = c.log.WithField("relay", instanceURL.String())
	c.log.Infof("relay connection established, server IP: %s", connectedIP(c.relayConn))

	c.serviceIsRunning = true
	c.stopFlag = newInternalStopFlag()
	internallyStoppedFlag := c.stopFlag
	c.watchMu.Lock()
	c.watchSeq++
	watchSeq := c.watchSeq
	c.alignedPeriod.Store(0)
	c.watchMu.Unlock()

	// Ask for the aligned heartbeat right after the auth response. A stock
	// server ignores the payload and stays stock.
	if period, ok := c.askedPeriod(); ok {
		if _, err := c.relayConn.Write(messages.MarshalHealthcheckWithPeriod(uint16(period / time.Second))); err != nil {
			c.log.Debugf("failed to send aligned heartbeat request: %s", err)
		}
	}
	c.startWatch(watchSeq, c.relayConn, internallyStoppedFlag)

	hc := healthcheck.NewReceiver(c.log)
	go c.listenForStopEvents(ctx, hc, c.relayConn, internallyStoppedFlag)

	c.wgReadLoop.Add(1)
	go c.readLoop(hc, c.relayConn, internallyStoppedFlag, watchSeq)

	return nil
}

// OpenConn create a new Conn for the destination peer ID. In case if the connection is in progress
// to the relay server, the function will block until the connection is established or timed out. Otherwise,
// it will return immediately.
// It block until the server confirm the peer is online.
// todo: what should happen if call with the same peerID with multiple times?
func (c *Client) OpenConn(ctx context.Context, dstPeerID string) (*Conn, error) {
	peerID := messages.HashID(dstPeerID)

	c.mu.Lock()
	if !c.serviceIsRunning {
		c.mu.Unlock()
		return nil, fmt.Errorf("relay connection is not established")
	}
	_, ok := c.conns[peerID]
	if ok {
		c.mu.Unlock()
		return nil, ErrConnAlreadyExists
	}

	c.log.Infof("prepare the relayed connection, waiting for remote peer: %s", peerID)

	c.muInstanceURL.Lock()
	instanceURL := c.instanceURL
	c.muInstanceURL.Unlock()

	container := newConnContainer(c.log, c, peerID, instanceURL)
	c.conns[peerID] = container
	earlyMsg, hasEarly := c.earlyMsgs.pop(peerID)
	c.mu.Unlock()

	if hasEarly {
		container.writeMsg(earlyMsg)
		c.log.Tracef("flushed buffered early message for peer: %s", peerID)
	}

	if err := c.stateSubscription.WaitToBeOnlineAndSubscribe(ctx, peerID); err != nil {
		c.log.Errorf("peer not available: %s, %s", peerID, err)
		c.mu.Lock()
		if savedContainer, ok := c.conns[peerID]; ok && savedContainer == container {
			delete(c.conns, peerID)
		}
		c.mu.Unlock()
		container.close(err)
		return nil, err
	}

	c.mu.Lock()
	if !c.serviceIsRunning {
		if savedContainer, ok := c.conns[peerID]; ok && savedContainer == container {
			delete(c.conns, peerID)
		}
		c.mu.Unlock()
		container.close(ErrServerDisconnected)
		return nil, fmt.Errorf("relay connection is not established")
	}
	c.mu.Unlock()

	c.log.Infof("remote peer is available: %s", peerID)
	return container.conn, nil
}

// ServerInstanceURL returns the address of the relay server. It could change after the close and reopen the connection.
func (c *Client) ServerInstanceURL() (string, error) {
	c.muInstanceURL.Lock()
	defer c.muInstanceURL.Unlock()
	if c.instanceURL == nil {
		return "", fmt.Errorf("relay connection is not established")
	}
	return c.instanceURL.String(), nil
}

// SetOnDisconnectListener sets a function that will be called when the connection to the relay server is closed.
func (c *Client) SetOnDisconnectListener(fn func(string)) {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()
	c.onDisconnectListener = fn
}

// HasConns returns true if there are connections.
func (c *Client) HasConns() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns) > 0
}

func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serviceIsRunning
}

// Close closes the connection to the relay server and all connections to other peers.
func (c *Client) Close() error {
	return c.close(true)
}

func (c *Client) connect(ctx context.Context) (*RelayAddr, error) {
	// A sweep cancels this context, so a dial started on the old network
	// aborts instead of waiting out its handshake timeout.
	var dial *sweep.Dial
	if c.netEvents != nil {
		dial = c.netEvents.StartDial(ctx)
	} else {
		dial = (*sweep.Sweeper)(nil).StartDial(ctx)
	}
	defer dial.Release()
	ctx = dial.Ctx()

	mode := transportModeFromEnv()
	dialers := c.getDialers(mode)

	var conn net.Conn
	if c.serverIP.IsValid() {
		var err error
		conn, err = c.dialRaceDirect(ctx, mode, dialers)
		if err != nil {
			c.log.Infof("dial via server IP %s failed, falling back to FQDN: %v", c.serverIP, err)
			conn = nil
		}
	}

	if conn == nil {
		rd := dialer.NewRaceDial(c.log, dialer.DefaultConnectionTimeout, c.connectionURL, dialers...)
		if mode.sequential() {
			rd.WithSequential()
		}
		var err error
		conn, err = rd.Dial(ctx)
		if err != nil {
			return nil, fmt.Errorf("dial via FQDN: %w", err)
		}
	}
	// Read the transport off the concrete connection: the sweeper's wrapper
	// embeds net.Conn only, so it does not promote Protocol().
	if tc, ok := conn.(transportConn); ok {
		c.transport = tc.Protocol()
	}
	c.maxMsgSize = maxMessageSize(conn)

	conn, err := dial.WrapConn(conn)
	if err != nil {
		return nil, fmt.Errorf("register connection: %w", err)
	}
	c.relayConn = conn
	c.datagramFallbackTriggered.Store(false)

	instanceURL, err := c.handShake(ctx)
	if err != nil {
		cErr := conn.Close()
		if cErr != nil {
			c.log.Errorf("failed to close connection: %s", cErr)
		}
		return nil, err
	}

	return instanceURL, nil
}

// dialRaceDirect dials c.serverIP, preserving the original FQDN as the TLS ServerName for SNI.
func (c *Client) dialRaceDirect(ctx context.Context, mode TransportMode, dialers []dialer.DialeFn) (net.Conn, error) {
	directURL, serverName, err := substituteHost(c.connectionURL, c.serverIP)
	if err != nil {
		return nil, fmt.Errorf("substitute host: %w", err)
	}

	c.log.Debugf("dialing via server IP %s (SNI=%s)", c.serverIP, serverName)

	rd := dialer.NewRaceDial(c.log, dialer.DefaultConnectionTimeout, directURL, dialers...).
		WithServerName(serverName)
	if mode.sequential() {
		rd.WithSequential()
	}
	return rd.Dial(ctx)
}

// substituteHost replaces the host portion of a rel/rels URL with ip,
// preserving the scheme and port. Returns the rewritten URL and the
// original host to use as the TLS ServerName, or empty if the original
// host is itself an IP literal (SNI requires a DNS name).
func substituteHost(serverURL string, ip netip.Addr) (string, string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", "", fmt.Errorf("parse %q: %w", serverURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid relay URL %q", serverURL)
	}
	if !ip.IsValid() {
		return "", "", errors.New("invalid server IP")
	}
	origHost := u.Hostname()
	if _, err := netip.ParseAddr(origHost); err == nil {
		origHost = ""
	}
	ip = ip.Unmap()
	newHost := ip.String()
	if ip.Is6() {
		newHost = "[" + newHost + "]"
	}
	if port := u.Port(); port != "" {
		u.Host = newHost + ":" + port
	} else {
		u.Host = newHost
	}
	return u.String(), origHost, nil
}

func (c *Client) handShake(ctx context.Context) (*RelayAddr, error) {
	msg, err := messages.MarshalAuthMsg(c.hashedID, c.authTokenStore.TokenBinary())
	if err != nil {
		c.log.Errorf("failed to marshal auth message: %s", err)
		return nil, err
	}

	_, err = c.relayConn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to send auth message: %s", err)
		return nil, err
	}
	buf := make([]byte, messages.MaxHandshakeRespSize)
	n, err := c.readWithTimeout(ctx, buf)
	if err != nil {
		c.log.Errorf("failed to read auth response: %s", err)
		return nil, err
	}

	_, err = messages.ValidateVersion(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("validate version: %w", err)
	}

	msgType, err := messages.DetermineServerMessageType(buf[:n])
	if err != nil {
		c.log.Errorf("failed to determine message type: %s", err)
		return nil, err
	}

	if msgType != messages.MsgTypeAuthResponse {
		c.log.Errorf("unexpected message type: %s", msgType)
		return nil, fmt.Errorf("unexpected message type")
	}

	addr, err := messages.UnmarshalAuthResponse(buf[:n])
	if err != nil {
		return nil, err
	}

	return &RelayAddr{addr: addr}, nil
}

func (c *Client) readLoop(hc *healthcheck.Receiver, relayConn net.Conn, internallyStoppedFlag *internalStopFlag, watchSeq int) {
	var (
		errExit error
		n       int
	)
	for {
		bufPtr := c.bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, errExit = relayConn.Read(buf)
		if errExit != nil {
			c.log.Infof("start to Relay read loop exit")
			c.mu.Lock()
			if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
				c.log.Errorf("failed to read message from relay server: %s", errExit)
			}
			c.mu.Unlock()
			c.bufPool.Put(bufPtr)
			break
		}

		buf = buf[:n]

		_, err := messages.ValidateVersion(buf)
		if err != nil {
			c.log.Errorf("failed to validate protocol version: %s", err)
			c.bufPool.Put(bufPtr)
			continue
		}

		msgType, err := messages.DetermineServerMessageType(buf)
		if err != nil {
			c.log.Errorf("failed to determine message type: %s", err)
			c.bufPool.Put(bufPtr)
			continue
		}

		if !c.handleMsg(msgType, buf, bufPtr, hc, relayConn, watchSeq, internallyStoppedFlag) {
			break
		}
	}

	hc.Stop()
	c.clearWatchGen(watchSeq)

	c.stateSubscription.Cleanup()
	c.wgReadLoop.Done()
	_ = c.close(false)
	c.notifyDisconnected()
}

func (c *Client) handleMsg(msgType messages.MsgType, buf []byte, bufPtr *[]byte, hc *healthcheck.Receiver, relayConn net.Conn, watchSeq int, internallyStoppedFlag *internalStopFlag) (continueLoop bool) {
	switch msgType {
	case messages.MsgTypeHealthCheck:
		c.handleHealthCheck(buf, hc, relayConn, watchSeq, internallyStoppedFlag)
		c.bufPool.Put(bufPtr)
	case messages.MsgTypeTransport:
		return c.handleTransportMsg(buf, bufPtr, internallyStoppedFlag)
	case messages.MsgTypePeersOnline:
		c.handlePeersOnlineMsg(buf)
		c.bufPool.Put(bufPtr)
		return true
	case messages.MsgTypePeersWentOffline:
		c.handlePeersWentOfflineMsg(buf)
		c.bufPool.Put(bufPtr)
		return true
	case messages.MsgTypeClose:
		c.log.Debugf("relay connection close by server")
		c.bufPool.Put(bufPtr)
		return false
	}

	return true
}

func (c *Client) handleHealthCheck(buf []byte, hc *healthcheck.Receiver, relayConn net.Conn, watchSeq int, internallyStoppedFlag *internalStopFlag) {
	c.switchAligned(buf, hc, relayConn, watchSeq)

	msg := messages.MarshalHealthcheck()
	if period := c.answerPeriod(); period > 0 {
		msg = messages.MarshalHealthcheckWithPeriod(uint16(period / time.Second))
	}
	_, wErr := c.relayConn.Write(msg)
	if wErr != nil {
		if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
			c.log.Errorf("failed to send heartbeat: %s", wErr)
		}
	}
	hc.Heartbeat()
}

// answerPeriod returns the period a health check answer carries: the
// confirmed one once aligned, else the requested one, so a server that
// missed the first frame switches at a later answer. Zero keeps the stock
// frame.
func (c *Client) answerPeriod() time.Duration {
	if period := c.AlignedPeriod(); period > 0 {
		return period
	}
	if period, ok := c.askedPeriod(); ok {
		return period
	}
	return 0
}

// askedPeriod returns the aligned heartbeat period this client asks for, ok
// false for none, also on a Client built without NewClient.
func (c *Client) askedPeriod() (time.Duration, bool) {
	if c.alignedRequest == nil {
		return 0, false
	}
	return c.alignedRequest()
}

// switchAligned moves the receiver to the aligned timeout at the first
// server health check that carries a valid period, and records every
// aligned server frame with hbwatch. relayConn and watchSeq are the
// connection and Connect sequence of the read loop that got the frame. A
// payload of one byte or a period of zero stays stock.
func (c *Client) switchAligned(buf []byte, hc *healthcheck.Receiver, relayConn net.Conn, watchSeq int) {
	periodSeconds, ok, err := messages.UnmarshalHealthcheckPeriod(buf)
	if err != nil {
		c.log.Tracef("ignoring health check period: %s", err)
		return
	}
	if !ok {
		return
	}
	period := alignedhb.ClampPeriod(time.Duration(periodSeconds) * time.Second)
	switched, current := c.storeAlignedPeriod(watchSeq, period)
	if !current {
		return
	}
	if switched {
		hc.SetTimeout(alignedhb.ReceiveTimeout(period))
		if err := keepalive.SetAligned(relayConn, period); err != nil && !errors.Is(err, keepalive.ErrNotTCP) {
			c.log.Debugf("failed to set TCP keepalive for heartbeat period %s: %v", period, err)
		}
		phase := alignedhb.Phase(c.hashedID, period)
		c.log.Infof("aligned heartbeat on, period %s, phase %d ms", period, phase.Milliseconds())
	}
	if c.watch.Load() {
		hbwatch.Seen(hbwatch.Relay, period)
	}
}

// storeAlignedPeriod records period for the connection of Connect sequence
// watchSeq and reports whether it changed. current is false once a newer
// Connect replaced that connection: an old read loop that drains its last
// frames must not mark the new connection aligned before its server does.
func (c *Client) storeAlignedPeriod(watchSeq int, period time.Duration) (switched, current bool) {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	if c.watchSeq != watchSeq {
		return false, false
	}
	return c.alignedPeriod.Swap(int64(period)) != int64(period), true
}

func (c *Client) handleTransportMsg(buf []byte, bufPtr *[]byte, internallyStoppedFlag *internalStopFlag) bool {
	peerID, payload, err := messages.UnmarshalTransportMsg(buf)
	if err != nil {
		if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
			c.log.Errorf("failed to parse transport message: %v", err)
		}

		c.bufPool.Put(bufPtr)
		return true
	}

	c.mu.Lock()
	if !c.serviceIsRunning {
		c.mu.Unlock()
		c.bufPool.Put(bufPtr)
		return false
	}
	container, ok := c.conns[*peerID]
	earlyBuf := c.earlyMsgs
	c.mu.Unlock()
	if !ok {
		msg := Msg{
			bufPool: c.bufPool,
			bufPtr:  bufPtr,
			Payload: payload,
		}
		if earlyBuf == nil || !earlyBuf.put(*peerID, msg) {
			c.log.Warnf("failed to buffer early message for peer: %s", peerID.String())
			c.bufPool.Put(bufPtr)
		} else {
			c.log.Debugf("buffered early transport message for peer: %s", peerID.String())
		}
		return true
	}
	msg := Msg{
		bufPool: c.bufPool,
		bufPtr:  bufPtr,
		Payload: payload,
	}
	container.writeMsg(msg)
	return true
}

func (c *Client) writeTo(containerRef *connContainer, dstID messages.PeerID, payload []byte) (int, error) {
	c.mu.Lock()
	current, ok := c.conns[dstID]
	c.mu.Unlock()
	if !ok {
		return 0, net.ErrClosed
	}

	if current != containerRef {
		return 0, net.ErrClosed
	}

	// todo: use buffer pool instead of create new transport msg.
	msg, err := messages.MarshalTransportMsg(dstID, payload)
	if err != nil {
		c.log.Errorf("failed to marshal transport message: %s", err)
		return 0, err
	}

	// the write always return with 0 length because the underling does not support the size feedback.
	conn := c.relayConn
	_, err = conn.Write(msg)
	if err != nil {
		if errors.Is(err, netErr.ErrDatagramTooLarge) {
			c.onDatagramTooLarge(conn, err)
		} else {
			c.log.Errorf("failed to write transport message: %s", err)
		}
	}
	return len(payload), err
}

// onDatagramTooLarge reacts to a datagram rejected as too large for the path.
// When a non-datagram transport is available, it records a fallback for this
// server and closes the connection so the reconnect avoids datagram-sized
// transports. A single fallback is triggered per connection regardless of how
// many oversized datagrams arrive. cause carries the datagram size and budget.
func (c *Client) onDatagramTooLarge(conn net.Conn, cause error) {
	// Handle one oversized datagram per connection; a burst triggers a single
	// fallback (and a single log line), not many.
	if !c.datagramFallbackTriggered.CompareAndSwap(false, true) {
		return
	}

	// If the selected mode offers no non-datagram transport (e.g. pinned to a
	// datagram-sized transport), reconnecting would just re-fail, so leave the
	// connection up rather than loop.
	if len(nonDatagramSized(c.baseDialers(transportModeFromEnv()))) == 0 {
		c.log.Warnf("%s, but no non-datagram transport is available, not falling back", cause)
		return
	}

	// Without the shared tracker a reconnect would just select the same
	// transport again and re-fail, so leave the connection up rather than loop.
	if c.transportFallback == nil {
		c.log.Debugf("%s, but no transport fallback configured, leaving connection up", cause)
		return
	}

	window := c.transportFallback.recordFailure(c.connectionURL)
	c.log.Warnf("%s, avoiding datagram-sized transport for %s", cause, window)

	if err := conn.Close(); err != nil {
		c.log.Debugf("close relay connection for transport fallback: %s", err)
	}
}

func (c *Client) listenForStopEvents(ctx context.Context, hc *healthcheck.Receiver, conn net.Conn, internalStopFlag *internalStopFlag) {
	for {
		select {
		case _, ok := <-hc.OnTimeout:
			if !ok {
				return
			}
			c.log.Errorf("health check timeout")
			internalStopFlag.set()
			if err := conn.Close(); err != nil {
				// ignore the err handling because the readLoop will handle it
				c.log.Warnf("failed to close connection: %s", err)
			}
			return
		case <-ctx.Done():
			err := c.close(true)
			if err != nil {
				c.log.Errorf("failed to teardown connection: %s", err)
			}
			return
		}
	}
}

func (c *Client) serverInstanceAddress() (string, netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := c.ServerInstanceURL()
	if err != nil {
		return "", netip.Addr{}, err
	}
	return addr, connectedIP(c.relayConn), nil
}

func (c *Client) closeAllConns() {
	for _, container := range c.conns {
		container.close(ErrServerDisconnected)
	}
	c.conns = make(map[messages.PeerID]*connContainer)

	c.earlyMsgs.close()
	c.earlyMsgs = newEarlyMsgBuffer()
}

func (c *Client) closeConnsByPeerID(peerIDs []messages.PeerID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, peerID := range peerIDs {
		container, ok := c.conns[peerID]
		if !ok {
			c.log.Warnf("can not close connection, peer not found: %s", peerID)
			continue
		}

		container.log.Infof("remote peer has been disconnected, free up connection: %s", peerID)
		container.close(ErrPeerDisconnected)
		delete(c.conns, peerID)
	}

	if err := c.stateSubscription.UnsubscribeStateChange(peerIDs); err != nil {
		c.log.Errorf("failed to unsubscribe from peer state change: %s, %s", peerIDs, err)
	}
}

func (c *Client) closeConn(containerRef *connContainer, id messages.PeerID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	current, ok := c.conns[id]
	if !ok {
		return net.ErrClosed
	}

	if current != containerRef {
		return fmt.Errorf("conn reference mismatch")
	}

	if err := c.stateSubscription.UnsubscribeStateChange([]messages.PeerID{id}); err != nil {
		current.log.Errorf("failed to unsubscribe from peer state change: %s", err)
	}

	c.log.Infof("free up connection to peer: %s", id)
	delete(c.conns, id)
	current.close(net.ErrClosed)

	return nil
}

func (c *Client) close(gracefullyExit bool) error {
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	var err error
	if !c.serviceIsRunning {
		c.mu.Unlock()
		c.log.Warn("relay connection was already marked as not running")
		return nil
	}
	c.serviceIsRunning = false
	c.transport = ""

	c.muInstanceURL.Lock()
	c.instanceURL = nil
	c.muInstanceURL.Unlock()

	c.log.Infof("closing all peer connections")
	c.closeAllConns()
	if gracefullyExit {
		c.writeCloseMsg()
	}
	err = c.relayConn.Close()
	c.mu.Unlock()

	c.log.Infof("waiting for read loop to close")
	c.wgReadLoop.Wait()
	c.log.Infof("relay connection closed")
	return err
}

func (c *Client) notifyDisconnected() {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()

	if c.onDisconnectListener == nil {
		return
	}
	go c.onDisconnectListener(c.connectionURL)
}

func (c *Client) writeCloseMsg() {
	msg := messages.MarshalCloseMsg()
	_, err := c.relayConn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to send close message: %s", err)
	}
}

func (c *Client) readWithTimeout(ctx context.Context, buf []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, serverResponseTimeout)
	defer cancel()

	readDone := make(chan struct{})
	var (
		n   int
		err error
	)

	go func() {
		n, err = c.relayConn.Read(buf)
		close(readDone)
	}()

	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("read operation timed out")
	case <-readDone:
		return n, err
	}
}

func (c *Client) handlePeersOnlineMsg(buf []byte) {
	peersID, err := messages.UnmarshalPeersOnlineMsg(buf)
	if err != nil {
		c.log.Errorf("failed to unmarshal peers online msg: %s", err)
		return
	}
	c.stateSubscription.OnPeersOnline(peersID)
}

func (c *Client) handlePeersWentOfflineMsg(buf []byte) {
	peersID, err := messages.UnMarshalPeersWentOffline(buf)
	if err != nil {
		c.log.Errorf("failed to unmarshal peers went offline msg: %s", err)
		return
	}
	c.stateSubscription.OnPeersWentOffline(peersID)
}

func connectedIP(conn net.Conn) netip.Addr {
	if conn == nil {
		return netip.Addr{}
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return netip.Addr{}
	}
	return extractIPLiteral(addr.String())
}

// extractIPLiteral returns the IP from address forms produced by the relay
// dialers (URL or host:port). Zero value if the host is not an IP.
func extractIPLiteral(s string) netip.Addr {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Host
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	host = strings.Trim(host, "[]")
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func maxMessageSize(conn net.Conn) int {
	if sc, ok := conn.(sizedConn); ok {
		return sc.MaxMessageSize()
	}
	return messages.MaxMessageSize
}
