package inspect

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/shared/management/domain"
)

// handleTLS processes a TLS connection for the kernel-mode path: extracts SNI,
// evaluates rules, and handles the connection internally.
// In envoy mode, allowed connections are forwarded to envoy instead of direct relay.
func (p *Proxy) handleTLS(ctx context.Context, pconn *peekConn, dst netip.AddrPort, src SourceInfo) error {
	result, err := p.inspectTLS(ctx, pconn, dst, src)
	if err != nil {
		return err
	}

	if result.PassthroughConn != nil {
		p.mu.RLock()
		envoy := p.envoy
		p.mu.RUnlock()

		if envoy != nil {
			return p.forwardToEnvoy(ctx, pconn, dst, src, envoy)
		}
		return p.tlsPassthrough(ctx, pconn, dst, "")
	}

	return nil
}

// inspectTLS extracts SNI, evaluates rules, and returns the result.
// For ActionAllow: returns the peekConn as PassthroughConn (caller relays).
// For ActionBlock/ActionInspect: handles internally and returns nil PassthroughConn.
func (p *Proxy) inspectTLS(ctx context.Context, pconn *peekConn, dst netip.AddrPort, src SourceInfo) (InspectResult, error) {
	// The first 5 bytes (TLS record header) are already peeked.
	// Extend to read the full TLS record so bytes remain in the buffer for passthrough.
	peeked := pconn.Peeked()
	recordLen := int(peeked[3])<<8 | int(peeked[4])
	if _, err := pconn.PeekMore(5 + recordLen); err != nil {
		return InspectResult{}, fmt.Errorf("read TLS record: %w", err)
	}

	hello, err := parseClientHelloFromBytes(pconn.Peeked())
	if err != nil {
		return InspectResult{}, fmt.Errorf("parse ClientHello: %w", err)
	}

	sni := hello.SNI
	proto := protoFromALPN(hello.ALPN)
	// Connection-level evaluation: pass empty path.
	action := p.evaluateAction(src.IP, sni, dst, proto, "")

	// If any rule for this domain has path patterns, force inspect so paths can
	// be checked per-request after MITM decryption.
	if action == ActionAllow && p.rules.HasPathRulesForDomain(sni) {
		p.log.Debugf("upgrading to inspect for %s (path rules exist)", sni.PunycodeString())
		action = ActionInspect
	}

	// Snapshot cert provider under lock for use in this connection.
	p.mu.RLock()
	certs := p.certs
	p.mu.RUnlock()

	switch action {
	case ActionBlock:
		p.log.Debugf("block: TLS to %s (SNI=%s)", dst, sni.PunycodeString())
		if certs != nil {
			return InspectResult{Action: ActionBlock}, p.tlsBlockPage(ctx, pconn, sni, certs)
		}
		return InspectResult{Action: ActionBlock}, ErrBlocked

	case ActionAllow:
		p.log.Tracef("allow: TLS passthrough to %s (SNI=%s)", dst, sni.PunycodeString())
		return InspectResult{Action: ActionAllow, PassthroughConn: pconn}, nil

	case ActionInspect:
		if certs == nil {
			p.log.Warnf("allow: %s (inspect requested but no MITM CA configured)", sni.PunycodeString())
			return InspectResult{Action: ActionAllow, PassthroughConn: pconn}, nil
		}
		err := p.tlsMITM(ctx, pconn, dst, sni, src, certs)
		return InspectResult{Action: ActionInspect}, err

	default:
		p.log.Warnf("block: unknown action %q for %s", action, sni.PunycodeString())
		return InspectResult{Action: ActionBlock}, ErrBlocked
	}
}

// tlsBlockPage completes a MITM TLS handshake with the client using a dynamic
// certificate, then serves an HTTP 403 block page so the user sees a clear
// message instead of a cryptic SSL error.
func (p *Proxy) tlsBlockPage(ctx context.Context, pconn *peekConn, sni domain.Domain, certs *CertProvider) error {
	hostname := sni.PunycodeString()

	// Force HTTP/1.1 only: block pages are simple responses, no need for h2
	tlsCfg := certs.GetTLSConfig()
	tlsCfg.NextProtos = []string{"http/1.1"}
	clientTLS := tls.Server(pconn, tlsCfg)
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		// Client may not trust our CA, handshake fails. That's expected.
		return fmt.Errorf("block page TLS handshake for %s: %w", hostname, err)
	}
	defer func() {
		if err := clientTLS.Close(); err != nil {
			p.log.Debugf("close block page TLS for %s: %v", hostname, err)
		}
	}()

	writeBlockResponse(clientTLS, nil, sni)
	return ErrBlocked
}

// tlsPassthrough connects to the destination and relays encrypted traffic
// without decryption. The peeked ClientHello bytes are replayed.
func (p *Proxy) tlsPassthrough(ctx context.Context, pconn *peekConn, dst netip.AddrPort, sni domain.Domain) error {
	remote, err := p.dialTCP(ctx, dst)
	if err != nil {
		return fmt.Errorf("dial %s: %w", dst, err)
	}
	defer func() {
		if err := remote.Close(); err != nil {
			p.log.Debugf("close remote for %s: %v", dst, err)
		}
	}()

	p.log.Tracef("allow: TLS passthrough to %s (SNI=%s)", dst, sni.PunycodeString())

	return relay(ctx, pconn, remote)
}

// tlsMITM terminates the client TLS connection with a dynamic certificate,
// establishes a new TLS connection to the real destination, and runs the
// HTTP inspection pipeline on the decrypted traffic.
func (p *Proxy) tlsMITM(ctx context.Context, pconn *peekConn, dst netip.AddrPort, sni domain.Domain, src SourceInfo, certs *CertProvider) error {
	hostname := sni.PunycodeString()

	// TLS handshake with client using dynamic cert
	clientTLS := tls.Server(pconn, certs.GetTLSConfig())
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("client TLS handshake for %s: %w", hostname, err)
	}
	defer func() {
		if err := clientTLS.Close(); err != nil {
			p.log.Debugf("close client TLS for %s: %v", hostname, err)
		}
	}()

	// TLS connection to real destination
	remoteTLS, err := p.dialTLS(ctx, dst, hostname)
	if err != nil {
		return fmt.Errorf("dial TLS %s (%s): %w", dst, hostname, err)
	}
	defer func() {
		if err := remoteTLS.Close(); err != nil {
			p.log.Debugf("close remote TLS for %s: %v", hostname, err)
		}
	}()

	negotiatedProto := clientTLS.ConnectionState().NegotiatedProtocol
	p.log.Tracef("inspect: MITM established for %s (proto=%s)", hostname, negotiatedProto)

	return p.inspectHTTP(ctx, clientTLS, remoteTLS, dst, sni, src, negotiatedProto)
}

// dialTLS connects to the destination with TLS, verifying the real server certificate.
func (p *Proxy) dialTLS(ctx context.Context, dst netip.AddrPort, serverName string) (net.Conn, error) {
	rawConn, err := p.dialTCP(ctx, dst)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if closeErr := rawConn.Close(); closeErr != nil {
			p.log.Debugf("close raw conn after TLS handshake failure: %v", closeErr)
		}
		return nil, fmt.Errorf("TLS handshake with %s: %w", serverName, err)
	}

	return tlsConn, nil
}

// protoFromALPN maps TLS ALPN protocol names to proxy ProtoType.
// Falls back to ProtoHTTPS when no recognized ALPN is present.
func protoFromALPN(alpn []string) ProtoType {
	for _, p := range alpn {
		switch p {
		case "h2":
			return ProtoH2
		case "h3": // unlikely in TLS, but handle anyway
			return ProtoH3
		}
	}
	// No ALPN or only "http/1.1": treat as HTTPS
	return ProtoHTTPS
}

// relay copies data bidirectionally between client and remote until one
// side closes or the context is cancelled.
func relay(ctx context.Context, client, remote net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(remote, client)
		cancel()
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(client, remote)
		cancel()
		errCh <- err
	}()

	var firstErr error
	for range 2 {
		if err := <-errCh; err != nil && firstErr == nil {
			if !isClosedErr(err) {
				firstErr = err
			}
		}
	}

	return firstErr
}

// evaluateAction runs rule evaluation and resolves the effective action.
// Pass empty path for connection-level (TLS), non-empty for request-level (HTTP).
func (p *Proxy) evaluateAction(src netip.Addr, sni domain.Domain, dst netip.AddrPort, proto ProtoType, path string) Action {
	return p.rules.Evaluate(src, sni, dst.Addr(), dst.Port(), proto, path)
}

// dialTCP dials the destination, blocking connections to loopback, link-local,
// multicast, and WG overlay network addresses.
func (p *Proxy) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	ip := dst.Addr().Unmap()
	if err := p.validateDialTarget(ip); err != nil {
		return nil, fmt.Errorf("dial %s: %w", dst, err)
	}
	return p.dialer.DialContext(ctx, "tcp", dst.String())
}

// validateDialTarget blocks destinations that should never be dialed by the proxy.
// Mirrors the route validation in systemops.validateRoute.
func (p *Proxy) validateDialTarget(addr netip.Addr) error {
	switch {
	case !addr.IsValid():
		return fmt.Errorf("invalid address")
	case addr.IsLoopback():
		return fmt.Errorf("loopback address not allowed")
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("link-local address not allowed")
	case addr.IsMulticast():
		return fmt.Errorf("multicast address not allowed")
	case p.wgNetwork.IsValid() && p.wgNetwork.Contains(addr):
		return fmt.Errorf("overlay network address not allowed")
	case p.localIPs != nil && p.localIPs.IsLocalIP(addr):
		return fmt.Errorf("local address not allowed")
	}
	return nil
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return err == io.EOF ||
		err == io.ErrClosedPipe ||
		err == net.ErrClosed ||
		err == context.Canceled
}
