package client

import (
	"context"
	"errors"
	"fmt"
	"math"
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

	// versionFallback, when set, records relay servers that accept only the v1
	// auth, so later connects to them skip the v2 attempt. Shared via the manager.
	versionFallback *versionFallback

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

	// enc stamps outgoing frames with the protocol version selected for the
	// current connection. Set by the handshake, like relayConn.
	enc messages.Encoder
	// alignedPeriod is the aligned heartbeat period of the current connection,
	// zero when the server selected a version without it.
	alignedPeriod time.Duration
	// alignedRequest returns the aligned heartbeat period to ask for, ok false
	// for none.
	alignedRequest func() (period time.Duration, ok bool)
	// authSeq is the sequence number of the signed phase the current
	// connection sent in its auth message, zero for none.
	authSeq    uint64
	maxMsgSize int
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

// SetVersionFallback wires the shared tracker of relay servers that accept only
// the v1 auth.
func (c *Client) SetVersionFallback(vf *versionFallback) {
	c.versionFallback = vf
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

	c.stateSubscription = NewPeersStateSubscription(c.log, c.relayConn, c.enc, c.closeConnsByPeerID)

	c.log = c.log.WithField("relay", instanceURL.String())
	c.log.Infof("relay connection established, server IP: %s", connectedIP(c.relayConn))

	c.serviceIsRunning = true

	internallyStoppedFlag := newInternalStopFlag()
	hc := c.newHealthCheckReceiver()
	go c.listenForStopEvents(ctx, hc, c.relayConn, internallyStoppedFlag)

	relayConn, connLog, version := c.relayConn, c.log, c.enc.Version()
	echo := newAlignedEcho(c.enc, c.hashedID, c.alignedPeriod, c.authSeq, connLog)
	reconnect := func() {
		connLog.Warnf("relay connection is stale, closing it like a health check timeout")
		c.healthCheckTimedOut(relayConn, internallyStoppedFlag)
	}
	unregisterStale := hbwatch.Register(hbwatch.Relay, hbwatch.Registration{
		Kind:          hbwatch.ActionReconnect,
		Stale:         reconnect,
		Correct:       echo.correct,
		Stream:        echo,
		Addr:          c.connectionURL,
		AlignedPeriod: c.alignedPeriod,
		Frames:        echo.frameCount,
	})

	c.wgReadLoop.Add(1)
	go func() {
		c.readLoop(hc, relayConn, version, echo, internallyStoppedFlag)
		unregisterStale()
	}()

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

// connect dials the relay server and authenticates. A server that closes the
// connection on the v2 auth predates version negotiation: it is dialed again
// with the v1 auth and remembered once that succeeds.
func (c *Client) connect(ctx context.Context) (*RelayAddr, error) {
	instanceURL, err := c.connectWithVersion(ctx, c.versionFallback.maxVersion(c.connectionURL))
	if err == nil && c.enc.Version() >= messages.ProtocolV2 {
		c.versionFallback.recordV2(c.connectionURL)
	}
	if !errors.Is(err, errV2AuthRejected) {
		return instanceURL, err
	}

	c.log.Infof("relay server closed the connection on the v2 auth, retrying with v1: %v", err)
	instanceURL, err = c.connectWithVersion(ctx, messages.ProtocolV1)
	if err != nil {
		return nil, fmt.Errorf("v1 retry after rejected v2 auth: %w", err)
	}
	c.versionFallback.recordV1Only(c.connectionURL)
	c.log.Infof("relay server accepts only the v1 auth, using v1 for it from now on")
	return instanceURL, nil
}

// connectWithVersion dials the relay server and authenticates with an auth
// message of at most maxVersion.
func (c *Client) connectWithVersion(ctx context.Context, maxVersion messages.ProtocolVersion) (*RelayAddr, error) {
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

	instanceURL, err := c.handShake(ctx, maxVersion)
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

// newHealthCheckReceiver returns the receiver for the current connection: one
// that waits for the aligned period when the server turned it on, else stock.
func (c *Client) newHealthCheckReceiver() *healthcheck.Receiver {
	if c.alignedPeriod > 0 {
		c.log.Infof("aligned heartbeat on, period %s", c.alignedPeriod)
		return healthcheck.NewAlignedReceiver(c.log, c.alignedPeriod)
	}
	return healthcheck.NewReceiver(c.log)
}

// authMsg returns the Auth message and the version it advertises. A client that
// asks for the aligned heartbeat advertises v2 with its period in the extension,
// any other client keeps the v1 auth. The envelope cannot carry an empty token,
// so without a token the auth stays v1 as well, and so it does when maxVersion
// is below v2.
func (c *Client) authMsg(maxVersion messages.ProtocolVersion) ([]byte, messages.ProtocolVersion, time.Duration, error) {
	token := c.authTokenStore.TokenBinary()
	period, ok := c.alignedRequest()
	if !ok || len(token) == 0 || maxVersion < messages.ProtocolV2 {
		msg, err := messages.MarshalAuthMsg(c.hashedID, token)
		return msg, messages.ProtocolV1, 0, err
	}
	ext, period, err := c.authExtension(period)
	if err != nil {
		return nil, 0, 0, err
	}
	msg, err := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).Auth(c.hashedID, token, ext)
	return msg, messages.ProtocolV2, period, err
}

// authExtension returns the auth extension with the period and, once the client
// has one, the phase Management signed. The period is then the one the phase was
// signed for, so the relay server can verify it.
func (c *Client) authExtension(requested time.Duration) ([]byte, time.Duration, error) {
	c.authSeq = 0
	stored, ok := alignedhb.LoadStoredPhase(c.hashedID)
	if !ok {
		period := min(requested, time.Duration(math.MaxUint16)*time.Second)
		ext, err := messages.MarshalAuthExtension(messages.AuthExtension{PeriodSeconds: uint16(period / time.Second)})
		return ext, period, err
	}
	ext, period, err := signedPhaseExtension(stored)
	if err != nil {
		return nil, 0, err
	}
	c.authSeq = stored.Seq
	return ext, period, nil
}

// signedPhaseExtension encodes a stored signed phase as the period and signed
// phase fields of the auth extension. The period is the one the phase was signed
// for, so the relay server can verify it.
func signedPhaseExtension(stored alignedhb.StoredPhase) ([]byte, time.Duration, error) {
	period := min(stored.Period, time.Duration(math.MaxUint16)*time.Second)
	ext, err := messages.MarshalAuthExtension(messages.AuthExtension{
		PeriodSeconds: uint16(period / time.Second),
		SignedPhase: &messages.AuthSignedPhase{
			PhaseMs:   uint32(stored.Signed.Phase.Milliseconds()),
			Day:       stored.Signed.Day,
			Signature: stored.Signed.Signature,
		},
	})
	return ext, period, err
}

// selectedVersion reads the version the server selected from its auth response.
// It must be one this client advertised or a lower one.
func selectedVersion(resp []byte, advertised messages.ProtocolVersion) (messages.ProtocolVersion, error) {
	version, err := messages.ReadVersion(resp)
	if err != nil {
		return 0, err
	}
	if version > advertised {
		return 0, fmt.Errorf("server selected %d above the advertised %d: %w", version, advertised, messages.ErrUnsupportedVersion)
	}
	return version, nil
}

func (c *Client) handShake(ctx context.Context, maxVersion messages.ProtocolVersion) (*RelayAddr, error) {
	msg, advertised, period, err := c.authMsg(maxVersion)
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
		return nil, fmt.Errorf("read auth response: %w", authRejectErr(ctx, advertised, err))
	}

	selected, err := selectedVersion(buf[:n], advertised)
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

	c.enc = messages.NewEncoder(selected, c.maxMsgSize)
	c.alignedPeriod = 0
	if selected >= messages.ProtocolV2 {
		c.alignedPeriod = period
		c.setAlignedKeepAlive(period)
	}
	return &RelayAddr{addr: addr}, nil
}

// setAlignedKeepAlive switches the TCP keepalive of the relay connection to the
// one for heartbeats every period. The connection was dialed stock, and a v1
// connection keeps that. QUIC has no TCP socket and is left as dialed.
func (c *Client) setAlignedKeepAlive(period time.Duration) {
	err := keepalive.SetAligned(c.relayConn, period)
	switch {
	case err == nil, errors.Is(err, keepalive.ErrNotTCP):
	default:
		c.log.Debugf("failed to set TCP keepalive for heartbeat period %s: %v", period, err)
	}
}

func (c *Client) readLoop(hc *healthcheck.Receiver, relayConn net.Conn, version messages.ProtocolVersion, echo *alignedEcho, internallyStoppedFlag *internalStopFlag) {
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

		err := messages.ValidateConnectionVersion(buf, version)
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

		if !c.handleMsg(msgType, buf, bufPtr, hc, echo, internallyStoppedFlag) {
			break
		}
	}

	c.noteDrop(version)
	hc.Stop()

	c.stateSubscription.Cleanup()
	c.wgReadLoop.Done()
	_ = c.close(false)
	c.notifyDisconnected()
}

// noteDrop tells the version fallback that a v1 connection dropped. The
// service still runs unless Close ended the connection, which is no drop.
func (c *Client) noteDrop(version messages.ProtocolVersion) {
	c.mu.Lock()
	dropped := c.serviceIsRunning
	c.mu.Unlock()
	if dropped && version < messages.ProtocolV2 {
		c.versionFallback.v1Dropped(c.connectionURL)
	}
}

func (c *Client) handleMsg(msgType messages.MsgType, buf []byte, bufPtr *[]byte, hc *healthcheck.Receiver, echo *alignedEcho, internallyStoppedFlag *internalStopFlag) (continueLoop bool) {
	if msgType != messages.MsgTypeHealthCheck {
		echo.frame()
	}
	switch msgType {
	case messages.MsgTypeHealthCheck:
		c.handleHealthCheck(buf, hc, echo, internallyStoppedFlag)
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

// handleHealthCheck answers a server health check. An aligned heartbeat goes
// to the watcher first, so a phase correction it triggers rides on this answer.
func (c *Client) handleHealthCheck(msg []byte, hc *healthcheck.Receiver, echo *alignedEcho, internallyStoppedFlag *internalStopFlag) {
	echo.observe(msg)
	_, wErr := c.relayConn.Write(echo.answer())
	if wErr != nil {
		if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
			c.log.Errorf("failed to send heartbeat: %s", wErr)
		}
	}
	hc.Heartbeat()
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
	msg := c.enc.Transport(dstID, payload)

	// the write always return with 0 length because the underling does not support the size feedback.
	conn := c.relayConn
	_, err := conn.Write(msg)
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
			c.healthCheckTimedOut(conn, internalStopFlag)
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

// healthCheckTimedOut closes the relay connection as a dead link. The read loop
// then exits, closes the peer conns and notifies the disconnect listener, which
// starts the reconnect.
func (c *Client) healthCheckTimedOut(conn net.Conn, internalStopFlag *internalStopFlag) {
	internalStopFlag.set()
	if err := conn.Close(); err != nil {
		// ignore the err handling because the readLoop will handle it
		c.log.Warnf("failed to close connection: %s", err)
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
	_, err := c.relayConn.Write(c.enc.CloseMsg())
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
