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

// agentClientHandshake runs the daemon's half against a freshly dialled agent
// connection: read the agent's challenge, answer it, then challenge the agent
// back and check its answer before any session bytes are proxied.
//
// viewOnly travels inside the daemon's tag, so an impostor cannot flip a
// read-only session into a controlling one by rewriting the byte in flight.
func agentClientHandshake(conn net.Conn, token []byte, viewOnly bool) error {
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

	flag := viewOnlyByte(viewOnly)
	reply := make([]byte, 0, agentMACLen+agentNonceLen+1)
	reply = append(reply, agentMAC(token, agentDaemonLabel, agentNonce, flag)...)
	reply = append(reply, daemonNonce...)
	reply = append(reply, flag...)
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
// returning the view-only flag the daemon authenticated.
func agentServerHandshake(conn net.Conn, token []byte) (bool, error) {
	if err := conn.SetDeadline(time.Now().Add(agentHandshakeTimeout)); err != nil {
		return false, fmt.Errorf("set handshake deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			log.Debugf("clear agent handshake deadline: %v", err)
		}
	}()

	agentNonce := make([]byte, agentNonceLen)
	if _, err := rand.Read(agentNonce); err != nil {
		return false, fmt.Errorf("read random: %w", err)
	}
	if _, err := conn.Write(agentNonce); err != nil {
		return false, fmt.Errorf("send challenge: %w", err)
	}

	buf := make([]byte, agentMACLen+agentNonceLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false, fmt.Errorf("read daemon response: %w", err)
	}
	daemonTag := buf[:agentMACLen]
	daemonNonce := buf[agentMACLen : agentMACLen+agentNonceLen]
	flag := buf[agentMACLen+agentNonceLen:]

	want := agentMAC(token, agentDaemonLabel, agentNonce, flag)
	if subtle.ConstantTimeCompare(daemonTag, want) != 1 {
		return false, fmt.Errorf("caller did not prove it holds the session token")
	}

	if _, err := conn.Write(agentMAC(token, agentAgentLabel, daemonNonce)); err != nil {
		return false, fmt.Errorf("send response: %w", err)
	}
	return flag[0] != 0, nil
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
func isProbeDisconnect(err error) bool {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return true
	case errors.Is(err, net.ErrClosed):
		return true
	case errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNRESET):
		return true
	default:
		return false
	}
}

// viewOnlyByte renders the flag as the single byte both tags cover.
func viewOnlyByte(viewOnly bool) []byte {
	if viewOnly {
		return []byte{1}
	}
	return []byte{0}
}
