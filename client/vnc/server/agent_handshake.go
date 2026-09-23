//go:build !js && !ios && !android

package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// The daemon and its per-session agent authenticate each other with the
// per-spawn token, over a challenge-response rather than by sending the token
// itself.
//
// Sending it was enough to prove the daemon's side, but it also handed the
// secret to whatever was listening. The socket lives in a directory only the
// console user and root may write to, so an impostor has to already be running
// as that user — but such a process could then take the token, answer as the
// agent, and sit between an authorized remote peer and the desktop, watching
// what they see and type. Neither end reveals the token now, and each refuses to
// continue until the other has proved it holds the same one.
//
// Both ends are the same binary: the daemon spawns the agent from its own
// executable, so there is no version skew between them to keep compatible.
const (
	// agentTokenLen is the size of the random per-spawn token in bytes. It is
	// the HMAC key both halves below are keyed on.
	agentTokenLen = 32

	// agentNonceLen is the size of each side's challenge.
	agentNonceLen = 32
	// agentMACLen is the size of an HMAC-SHA256 tag.
	agentMACLen = sha256.Size
	// agentHandshakeTimeout bounds the whole exchange. Both ends are local
	// processes, so this only has to cover scheduling, never a network.
	agentHandshakeTimeout = 5 * time.Second

	// maxAgentPeerAddrLen is the longest peer address the grant can carry; its
	// length travels as one byte.
	maxAgentPeerAddrLen = 255
)

// Domain separation, so a tag one side produces can never be replayed as the
// other side's answer.
var (
	agentDaemonLabel = []byte("netbird-vnc-daemon")
	agentAgentLabel  = []byte("netbird-vnc-agent")
)

// agentMAC tags the label and the parts under a token.
func agentMAC(token, label []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, token)
	mac.Write(label)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

// agentGrant is what the daemon authenticates to the agent for one proxied
// connection: whether it is view-only, and the address of the remote peer the
// daemon accepted, which the agent otherwise only sees as the local socket.
type agentGrant struct {
	viewOnly bool
	peerAddr string
}

// encode renders the grant as the bytes the daemon's tag covers: the view-only
// byte, a one-byte address length, then the address.
func (g agentGrant) encode() ([]byte, error) {
	if len(g.peerAddr) > maxAgentPeerAddrLen {
		return nil, fmt.Errorf("peer address of %d bytes exceeds %d", len(g.peerAddr), maxAgentPeerAddrLen)
	}
	b := make([]byte, 0, 2+len(g.peerAddr))
	b = append(b, viewOnlyByte(g.viewOnly)...)
	b = append(b, byte(len(g.peerAddr)))
	return append(b, g.peerAddr...), nil
}

// agentClientHandshake runs the daemon's half against a freshly dialled agent
// connection: read the agent's challenge, answer it, then challenge the agent
// back and check its answer before any session bytes are proxied.
//
// The grant travels inside the daemon's tag, so an impostor cannot flip a
// read-only session into a controlling one, or change the reported peer, by
// rewriting bytes in flight.
func agentClientHandshake(conn net.Conn, token []byte, grant agentGrant) error {
	payload, err := grant.encode()
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(agentHandshakeTimeout)); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			log.Debugf("clear agent handshake deadline: %v", err)
		}
	}()

	agentNonce := make([]byte, agentNonceLen)
	if _, err := io.ReadFull(conn, agentNonce); err != nil {
		return fmt.Errorf("read agent challenge: %w", err)
	}

	daemonNonce := make([]byte, agentNonceLen)
	if _, err := rand.Read(daemonNonce); err != nil {
		return fmt.Errorf("read random: %w", err)
	}

	reply := make([]byte, 0, agentMACLen+agentNonceLen+len(payload))
	reply = append(reply, agentMAC(token, agentDaemonLabel, agentNonce, payload)...)
	reply = append(reply, daemonNonce...)
	reply = append(reply, payload...)
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("send handshake response: %w", err)
	}

	agentTag := make([]byte, agentMACLen)
	if _, err := io.ReadFull(conn, agentTag); err != nil {
		return fmt.Errorf("read agent response: %w", err)
	}
	want := agentMAC(token, agentAgentLabel, daemonNonce)
	if subtle.ConstantTimeCompare(agentTag, want) != 1 {
		return fmt.Errorf("agent did not prove it holds the session token")
	}
	return nil
}

// agentServerHandshake runs the agent's half against an accepted connection,
// returning the grant the daemon authenticated.
func agentServerHandshake(conn net.Conn, token []byte) (agentGrant, error) {
	var none agentGrant
	if err := conn.SetDeadline(time.Now().Add(agentHandshakeTimeout)); err != nil {
		return none, fmt.Errorf("set handshake deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			log.Debugf("clear agent handshake deadline: %v", err)
		}
	}()

	agentNonce := make([]byte, agentNonceLen)
	if _, err := rand.Read(agentNonce); err != nil {
		return none, fmt.Errorf("read random: %w", err)
	}
	if _, err := conn.Write(agentNonce); err != nil {
		return none, fmt.Errorf("send challenge: %w", err)
	}

	head := make([]byte, agentMACLen+agentNonceLen+2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return none, fmt.Errorf("read daemon response: %w", err)
	}
	daemonTag := head[:agentMACLen]
	daemonNonce := head[agentMACLen : agentMACLen+agentNonceLen]
	addr := make([]byte, head[len(head)-1])
	if _, err := io.ReadFull(conn, addr); err != nil {
		return none, fmt.Errorf("read daemon response: %w", err)
	}
	payload := slices.Concat(head[agentMACLen+agentNonceLen:], addr)

	want := agentMAC(token, agentDaemonLabel, agentNonce, payload)
	if subtle.ConstantTimeCompare(daemonTag, want) != 1 {
		return none, fmt.Errorf("caller did not prove it holds the session token")
	}

	if _, err := conn.Write(agentMAC(token, agentAgentLabel, daemonNonce)); err != nil {
		return none, fmt.Errorf("send response: %w", err)
	}
	return agentGrant{viewOnly: payload[0] != 0, peerAddr: string(addr)}, nil
}

// isProbeDisconnect reports whether err is a peer that connected and left
// without speaking.
//
// The daemon's own readiness check dials the agent socket and closes it
// immediately, and it is not alone: anything probing the socket for liveness
// does the same. Since the agent now writes its challenge first, such a probe
// surfaces as a failed write (a reset or broken pipe) as often as a failed
// read, and logging either at warning level would fill the daemon log with
// entries for something entirely expected.
//
// io.ErrUnexpectedEOF is deliberately not here: that is a peer that sent part
// of a handshake and then went away, which is an aborted or malformed
// authentication attempt rather than a probe, and has to stay visible.
func isProbeDisconnect(err error) bool {
	switch {
	case errors.Is(err, io.EOF):
		return true
	case errors.Is(err, net.ErrClosed):
		return true
	case errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNRESET):
		return true
	default:
		return isPipeDisconnect(err)
	}
}

// viewOnlyByte renders the flag as the single byte both tags cover.
func viewOnlyByte(viewOnly bool) []byte {
	if viewOnly {
		return []byte{1}
	}
	return []byte{0}
}

// peerAddrConn reports the remote peer the daemon authenticated in the grant
// as the connection's remote address, in place of the local socket the agent
// actually accepted on.
type peerAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *peerAddrConn) RemoteAddr() net.Addr { return c.remote }

// withGrantPeer wraps conn so RemoteAddr returns the grant's peer address. A
// grant without a parseable address leaves conn as it is.
func withGrantPeer(conn net.Conn, grant agentGrant) net.Conn {
	if grant.peerAddr == "" {
		return conn
	}
	ap, err := netip.ParseAddrPort(grant.peerAddr)
	if err != nil {
		log.Debugf("agent grant peer address %q: %v", grant.peerAddr, err)
		return conn
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	return &peerAddrConn{Conn: conn, remote: net.TCPAddrFromAddrPort(ap)}
}
