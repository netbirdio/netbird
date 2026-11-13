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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/netevents/sweep"
	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
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

func newConnContainer(log *log.Entry, s *session, peerID messages.PeerID, instanceURL *RelayAddr) *connContainer {
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

	// bind conn to the session
	cn.writeFn = func(dstID messages.PeerID, payload []byte) (int, error) {
		return s.writeTo(cc, dstID, payload)
	}
	cn.closeFn = func(dstID messages.PeerID) error {
		return s.closeConn(cc, dstID)
	}
	cn.localAddrFn = func() net.Addr {
		return s.conn.LocalAddr()
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

	session   *session
	mu        sync.Mutex // protect session
	connectMu sync.Mutex

	mtu uint16

	// transportFallback, when set, records datagram-too-large failures so a
	// datagram-sized transport is avoided on subsequent connects. Shared via
	// the manager.
	transportFallback *transportFallback

	// netEvents registers the relay dial for the network change sweep; the
	// read loop reports the disconnect and the guard reconnects. Shared via
	// the manager.
	netEvents NetEvents
}

// Transport returns the negotiated relay transport of the current connection,
// or an empty string when not connected.
func (c *Client) Transport() string {
	s := c.currentSession()
	if s == nil {
		return ""
	}
	return s.transport
}

// SetTransportFallback wires the shared datagram-transport fallback tracker.
func (c *Client) SetTransportFallback(tf *transportFallback) {
	c.transportFallback = tf
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
	}

	c.log.Infof("create new relay connection: local peerID: %s, local peer hashedID: %s", peerID, hashedID)
	return c
}

// Connect establishes a connection to the relay server. It blocks until the connection is established or an error occurs.
func (c *Client) Connect(ctx context.Context) error {
	_, err := c.ConnectSession(ctx)
	return err
}

// OpenConn create a new Conn for the destination peer ID. In case if the connection is in progress
// to the relay server, the function will block until the connection is established or timed out. Otherwise,
// it will return immediately.
// It block until the server confirm the peer is online.
// todo: what should happen if call with the same peerID with multiple times?
func (c *Client) OpenConn(ctx context.Context, dstPeerID string) (*Conn, error) {
	c.connectMu.Lock()
	s := c.currentSession()
	c.connectMu.Unlock()
	if s == nil {
		return nil, fmt.Errorf("relay connection is not established")
	}
	return s.OpenConn(ctx, messages.HashID(dstPeerID))
}

// ServerInstanceURL returns the address of the relay server. It could change after the close and reopen the connection.
func (c *Client) ServerInstanceURL() (string, error) {
	s := c.currentSession()
	if s == nil {
		return "", fmt.Errorf("relay connection is not established")
	}
	return s.instanceURL.String(), nil
}

// HasConns returns true if there are connections.
func (c *Client) HasConns() bool {
	s := c.currentSession()
	return s != nil && s.HasConns()
}

func (c *Client) Ready() bool {
	return c.currentSession() != nil
}

// Close closes the connection to the relay server and all connections to other peers.
func (c *Client) Close() error {
	c.connectMu.Lock()
	s := c.currentSession()
	c.connectMu.Unlock()
	if s == nil {
		return nil
	}

	err := s.Close(true)
	s.Wait(context.Background())
	return err
}

func (c *Client) ConnectSession(ctx context.Context) (*session, error) {
	c.log.Infof("connecting to relay server")
	c.connectMu.Lock()
	defer c.connectMu.Unlock()

	if s := c.currentSession(); s != nil {
		return s, nil
	}

	s, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.session = s
	c.mu.Unlock()

	s.log.Infof("relay connection established, server IP: %s", connectedIP(s.conn))

	go s.ListenForStopEvents(ctx)
	go s.ReadLoop()

	return s, nil
}

func (c *Client) DetachSession(s *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == s {
		c.session = nil
	}
}

func (c *Client) currentSession() *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

func (c *Client) connect(ctx context.Context) (*session, error) {
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
	var transport string
	if tc, ok := conn.(transportConn); ok {
		transport = tc.Protocol()
	}

	conn, err := dial.WrapConn(conn)
	if err != nil {
		return nil, fmt.Errorf("register connection: %w", err)
	}

	instanceURL, err := c.handShake(ctx, conn)
	if err != nil {
		cErr := conn.Close()
		if cErr != nil {
			c.log.Errorf("failed to close connection: %s", cErr)
		}
		return nil, err
	}

	return newSession(c, conn, instanceURL, transport), nil
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

func (c *Client) handShake(ctx context.Context, conn net.Conn) (*RelayAddr, error) {
	msg, err := messages.MarshalAuthMsg(c.hashedID, c.authTokenStore.TokenBinary())
	if err != nil {
		c.log.Errorf("failed to marshal auth message: %s", err)
		return nil, err
	}

	_, err = conn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to send auth message: %s", err)
		return nil, err
	}
	buf := make([]byte, messages.MaxHandshakeRespSize)
	n, err := c.readWithTimeout(ctx, conn, buf)
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

func (c *Client) serverInstanceAddress() (string, netip.Addr, error) {
	s := c.currentSession()
	if s == nil {
		return "", netip.Addr{}, fmt.Errorf("relay connection is not established")
	}
	return s.instanceURL.String(), connectedIP(s.conn), nil
}

func (c *Client) readWithTimeout(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, serverResponseTimeout)
	defer cancel()

	readDone := make(chan struct{})
	var (
		n   int
		err error
	)

	go func() {
		n, err = conn.Read(buf)
		close(readDone)
	}()

	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("read operation timed out")
	case <-readDone:
		return n, err
	}
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
