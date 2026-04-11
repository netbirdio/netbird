package inspect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ErrBlocked is returned when a connection is denied by proxy policy.
var ErrBlocked = errors.New("connection blocked by proxy policy")

const (
	// headerReadTimeout is the deadline for reading the initial protocol header.
	// Prevents slow loris attacks where a client opens a connection but sends data slowly.
	headerReadTimeout = 10 * time.Second

	// idleTimeout is the deadline for idle connections between HTTP requests.
	idleTimeout = 120 * time.Second
)

// Proxy is the inspection engine for traffic passing through a NetBird
// routing peer. It handles protocol detection, rule evaluation, MITM TLS
// decryption, ICAP delegation, and external proxy forwarding.
type Proxy struct {
	config Config
	rules  *RuleEngine
	certs  *CertProvider
	icap   *ICAPClient
	// envoy is nil unless mode is ModeEnvoy.
	envoy *envoyManager
	// dialer is the outbound dialer (with SO_MARK cleared on Linux).
	dialer net.Dialer
	log    *log.Entry
	// wgNetwork is the WG overlay prefix; dial targets inside it are blocked.
	wgNetwork netip.Prefix
	// localIPs reports the routing peer's own IPs; dial targets are blocked.
	localIPs LocalIPChecker
	// listener is the TPROXY/REDIRECT listener for kernel mode.
	listener net.Listener

	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

// LocalIPChecker reports whether an IP belongs to the local machine.
type LocalIPChecker interface {
	IsLocalIP(netip.Addr) bool
}

// New creates a transparent proxy with the given configuration.
func New(ctx context.Context, logger *log.Entry, config Config) (*Proxy, error) {
	ctx, cancel := context.WithCancel(ctx)

	p := &Proxy{
		config:    config,
		rules:     NewRuleEngine(logger, config.DefaultAction),
		dialer:    newOutboundDialer(),
		log:       logger,
		wgNetwork: config.WGNetwork,
		localIPs:  config.LocalIPChecker,
		ctx:       ctx,
		cancel:    cancel,
	}

	p.rules.UpdateRules(config.Rules, config.DefaultAction)

	// Initialize MITM certificate provider
	if config.TLS != nil {
		p.certs = NewCertProvider(config.TLS.CA, config.TLS.CAKey)
	}

	// Initialize ICAP client
	if config.ICAP != nil {
		p.icap = NewICAPClient(logger, config.ICAP)
	}

	// Start envoy sidecar if configured
	if config.Mode == ModeEnvoy {
		envoyLog := logger.WithField("sidecar", "envoy")
		em, err := startEnvoy(ctx, envoyLog, config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("start envoy sidecar: %w", err)
		}
		p.envoy = em
	}

	// Start TPROXY listener for kernel mode
	if config.ListenAddr.IsValid() {
		ln, err := newTPROXYListener(logger, config.ListenAddr, netip.Prefix{})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("start TPROXY listener on %s: %w", config.ListenAddr, err)
		}
		p.listener = ln
		go p.acceptLoop(ln)
	}

	return p, nil
}

// HandleTCP is the entry point for TCP connections from the userspace forwarder.
// It determines the protocol (TLS or plaintext HTTP), evaluates rules,
// and either blocks, passes through, inspects, or forwards to an external proxy.
func (p *Proxy) HandleTCP(ctx context.Context, clientConn net.Conn, dst netip.AddrPort, src SourceInfo) error {
	defer func() {
		if err := clientConn.Close(); err != nil {
			p.log.Debugf("close client conn: %v", err)
		}
	}()

	p.mu.RLock()
	mode := p.config.Mode
	p.mu.RUnlock()

	if mode == ModeExternal {
		pconn := newPeekConn(clientConn)
		return p.handleExternal(ctx, pconn, dst)
	}

	// Envoy and builtin modes both peek the protocol header for rule evaluation.
	// Envoy mode forwards non-blocked traffic to envoy; builtin mode handles all locally.
	// TLS blocks are handled by Go (instant close) since envoy can't cleanly RST a TLS connection.

	// Built-in and envoy mode: peek 5 bytes (TLS record header size) to determine protocol.
	// Set a read deadline to prevent slow loris attacks.
	if err := clientConn.SetReadDeadline(time.Now().Add(headerReadTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	pconn := newPeekConn(clientConn)
	header, err := pconn.Peek(5)
	if err != nil {
		return fmt.Errorf("peek protocol header: %w", err)
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear read deadline: %w", err)
	}

	if isTLSHandshake(header[0]) {
		return p.handleTLS(ctx, pconn, dst, src)
	}

	if isHTTPMethod(header) {
		return p.handlePlainHTTP(ctx, pconn, dst, src)
	}

	// Not TLS and not HTTP: evaluate rules with ProtoOther.
	// If no rule explicitly allows "other", this falls through to the default action.
	action := p.rules.Evaluate(src.IP, "", dst.Addr(), dst.Port(), ProtoOther, "")
	if action == ActionAllow {
		remote, err := p.dialTCP(ctx, dst)
		if err != nil {
			return fmt.Errorf("dial for passthrough: %w", err)
		}
		defer func() {
			if err := remote.Close(); err != nil {
				p.log.Debugf("close remote conn: %v", err)
			}
		}()
		return relay(ctx, pconn, remote)
	}

	p.log.Debugf("block: non-HTTP/TLS to %s (action=%s, first bytes: %x)", dst, action, header)
	return ErrBlocked
}

// InspectTCP evaluates rules for a TCP connection and returns the result.
// Unlike HandleTCP, it can return early for allow decisions, letting the caller
// handle the relay (USP forwarder passthrough optimization).
//
// When InspectResult.PassthroughConn is non-nil, ownership transfers to the caller:
// the caller must close the connection and relay traffic. The engine does not close it.
//
// When PassthroughConn is nil, the engine handled everything internally
// (block, inspect/MITM, or plain HTTP inspection) and closed the connection.
func (p *Proxy) InspectTCP(ctx context.Context, clientConn net.Conn, dst netip.AddrPort, src SourceInfo) (InspectResult, error) {
	p.mu.RLock()
	mode := p.config.Mode
	envoy := p.envoy
	p.mu.RUnlock()

	// External mode: handle internally, engine owns the connection.
	if mode == ModeExternal {
		defer func() {
			if err := clientConn.Close(); err != nil {
				p.log.Debugf("close client conn: %v", err)
			}
		}()
		pconn := newPeekConn(clientConn)
		err := p.handleExternal(ctx, pconn, dst)
		return InspectResult{Action: ActionAllow}, err
	}

	// Peek protocol header.
	if err := clientConn.SetReadDeadline(time.Now().Add(headerReadTimeout)); err != nil {
		clientConn.Close()
		return InspectResult{}, fmt.Errorf("set read deadline: %w", err)
	}
	pconn := newPeekConn(clientConn)
	header, err := pconn.Peek(5)
	if err != nil {
		clientConn.Close()
		return InspectResult{}, fmt.Errorf("peek protocol header: %w", err)
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		clientConn.Close()
		return InspectResult{}, fmt.Errorf("clear read deadline: %w", err)
	}

	// TLS: may return passthrough for allow.
	if isTLSHandshake(header[0]) {
		result, err := p.inspectTLS(ctx, pconn, dst, src)
		if err != nil && result.PassthroughConn == nil {
			clientConn.Close()
			return result, err
		}
		// Envoy mode: forward allowed TLS to envoy instead of returning passthrough.
		if result.PassthroughConn != nil && envoy != nil {
			defer clientConn.Close()
			envoyErr := p.forwardToEnvoy(ctx, pconn, dst, src, envoy)
			return InspectResult{Action: ActionAllow}, envoyErr
		}
		return result, err
	}

	// Plain HTTP: in envoy mode, forward to envoy for L7 processing.
	// In builtin mode, inspect per-request locally.
	if isHTTPMethod(header) {
		defer func() {
			if err := clientConn.Close(); err != nil {
				p.log.Debugf("close client conn: %v", err)
			}
		}()
		if envoy != nil {
			err := p.forwardToEnvoy(ctx, pconn, dst, src, envoy)
			return InspectResult{Action: ActionAllow}, err
		}
		err := p.handlePlainHTTP(ctx, pconn, dst, src)
		return InspectResult{Action: ActionInspect}, err
	}

	// Other protocol: evaluate rules.
	action := p.rules.Evaluate(src.IP, "", dst.Addr(), dst.Port(), ProtoOther, "")
	if action == ActionAllow {
		// Envoy mode: forward to envoy.
		if envoy != nil {
			defer clientConn.Close()
			err := p.forwardToEnvoy(ctx, pconn, dst, src, envoy)
			return InspectResult{Action: ActionAllow}, err
		}
		return InspectResult{Action: ActionAllow, PassthroughConn: pconn}, nil
	}

	p.log.Debugf("block: non-HTTP/TLS to %s (action=%s, first bytes: %x)", dst, action, header)
	clientConn.Close()
	return InspectResult{Action: ActionBlock}, ErrBlocked
}

// HandleUDPPacket inspects a UDP packet for QUIC Initial packets.
// Returns the action to take: ActionAllow to continue normal forwarding,
// ActionBlock to drop the packet.
// Non-QUIC packets always return ActionAllow.
func (p *Proxy) HandleUDPPacket(data []byte, dst netip.AddrPort, src SourceInfo) Action {
	if len(data) < 5 {
		return ActionAllow
	}

	// Check for QUIC Long Header
	if data[0]&0x80 == 0 {
		return ActionAllow
	}

	sni, err := ExtractQUICSNI(data)
	if err != nil {
		// Can't parse QUIC, allow through (could be non-QUIC UDP)
		p.log.Tracef("QUIC SNI extraction failed for %s: %v", dst, err)
		return ActionAllow
	}

	if sni == "" {
		return ActionAllow
	}

	action := p.rules.Evaluate(src.IP, sni, dst.Addr(), dst.Port(), ProtoH3, "")

	if action == ActionBlock {
		p.log.Debugf("block: QUIC to %s (SNI=%s)", dst, sni.PunycodeString())
		return ActionBlock
	}

	// QUIC can't be MITMed, treat Inspect as Allow
	if action == ActionInspect {
		p.log.Debugf("allow: QUIC to %s (SNI=%s), MITM not supported for QUIC", dst, sni.PunycodeString())
	} else {
		p.log.Tracef("allow: QUIC to %s (SNI=%s)", dst, sni.PunycodeString())
	}

	return ActionAllow
}

// handlePlainHTTP handles plaintext HTTP connections.
func (p *Proxy) handlePlainHTTP(ctx context.Context, pconn *peekConn, dst netip.AddrPort, src SourceInfo) error {
	remote, err := p.dialTCP(ctx, dst)
	if err != nil {
		return fmt.Errorf("dial %s: %w", dst, err)
	}
	defer func() {
		if err := remote.Close(); err != nil {
			p.log.Debugf("close remote for %s: %v", dst, err)
		}
	}()

	// For plaintext HTTP, always inspect (we can see the traffic)
	return p.inspectHTTP(ctx, pconn, remote, dst, "", src, "http/1.1")
}

// UpdateConfig replaces the inspection engine configuration at runtime.
func (p *Proxy) UpdateConfig(config Config) {
	p.log.Debugf("config update: mode=%s rules=%d default=%s has_tls=%v has_icap=%v",
		config.Mode, len(config.Rules), config.DefaultAction, config.TLS != nil, config.ICAP != nil)

	p.mu.Lock()

	p.config = config
	p.rules.UpdateRules(config.Rules, config.DefaultAction)

	// Update MITM provider
	if config.TLS != nil {
		p.certs = NewCertProvider(config.TLS.CA, config.TLS.CAKey)
	} else {
		p.certs = nil
	}

	// Swap ICAP client under lock, close the old one outside to avoid blocking.
	var oldICAP *ICAPClient
	if config.ICAP != nil {
		oldICAP = p.icap
		p.icap = NewICAPClient(p.log, config.ICAP)
	} else {
		oldICAP = p.icap
		p.icap = nil
	}

	// If switching away from envoy mode, clear and stop the old envoy.
	var oldEnvoy *envoyManager
	if config.Mode != ModeEnvoy && p.envoy != nil {
		oldEnvoy = p.envoy
		p.envoy = nil
	}

	envoy := p.envoy

	p.mu.Unlock()

	if oldICAP != nil {
		oldICAP.Close()
	}

	if oldEnvoy != nil {
		oldEnvoy.Stop()
	}

	// Reload envoy config if still in envoy mode.
	if envoy != nil && config.Mode == ModeEnvoy {
		if err := envoy.Reload(config); err != nil {
			p.log.Errorf("inspect: envoy config reload: %v", err)
		}
	}
}

// Mode returns the current proxy operating mode.
func (p *Proxy) Mode() ProxyMode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config.Mode
}

// ListenPort returns the port to use for kernel-mode nftables REDIRECT.
// For builtin mode: the TPROXY listener port.
// For envoy mode: the envoy listener port (nftables redirects directly to envoy).
// Returns 0 if no listener is active.
func (p *Proxy) ListenPort() uint16 {
	p.mu.RLock()
	envoy := p.envoy
	p.mu.RUnlock()

	if envoy != nil {
		return envoy.listenPort
	}
	if p.listener == nil {
		return 0
	}
	tcpAddr, ok := p.listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return uint16(tcpAddr.Port)
}

// Close shuts down the proxy and releases resources.
func (p *Proxy) Close() error {
	p.cancel()

	p.mu.Lock()
	envoy := p.envoy
	p.envoy = nil
	icap := p.icap
	p.icap = nil
	p.mu.Unlock()

	if envoy != nil {
		envoy.Stop()
	}

	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			p.log.Debugf("close TPROXY listener: %v", err)
		}
	}

	if icap != nil {
		icap.Close()
	}

	return nil
}

// acceptLoop accepts connections from the redirected listener (kernel mode).
// Connections arrive via nftables REDIRECT; original destination is read from conntrack.
func (p *Proxy) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			p.log.Debugf("accept error: %v", err)
			continue
		}

		go func() {
			// Read original destination from conntrack (SO_ORIGINAL_DST).
			// nftables REDIRECT changes dst to the local WG IP:proxy_port,
			// but conntrack preserves the real destination.
			dstAddr, err := getOriginalDst(conn)
			if err != nil {
				p.log.Debugf("get original dst: %v", err)
				if closeErr := conn.Close(); closeErr != nil {
					p.log.Debugf("close conn: %v", closeErr)
				}
				return
			}

			p.log.Tracef("accepted: %s -> %s (original dst %s)",
				conn.RemoteAddr(), conn.LocalAddr(), dstAddr)

			srcAddr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
			if err != nil {
				p.log.Debugf("parse source: %v", err)
				if closeErr := conn.Close(); closeErr != nil {
					p.log.Debugf("close conn: %v", closeErr)
				}
				return
			}

			src := SourceInfo{
				IP: srcAddr.Addr().Unmap(),
			}

			if err := p.HandleTCP(p.ctx, conn, dstAddr, src); err != nil && !errors.Is(err, ErrBlocked) {
				p.log.Debugf("connection to %s: %v", dstAddr, err)
			}
		}()
	}
}
