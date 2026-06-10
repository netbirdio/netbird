//go:build !js && !ios && !android

package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/flynn/noise"
	log "github.com/sirupsen/logrus"
)

var vncIdentityMagic = []byte("NBV3")

// Noise_IK_25519_ChaChaPoly_SHA256 message sizes (with empty payloads).
//
//	msg1 = e(32) + s_AEAD(32+16) + payload_AEAD(0+16) = 96 bytes
//	msg2 = e(32) + payload_AEAD(0+16) = 48 bytes
const (
	noiseInitiatorMsgLen = 96
	noiseResponderMsgLen = 48
)

// vncNoiseSuite pins the cipher suite for the VNC handshake. Changing
// it requires bumping vncIdentityMagic so old clients fail closed.
var vncNoiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// vncNoisePrologueMagic prefixes the Noise prologue. Both sides mix the
// magic + mode byte + length-prefixed username into the handshake hash
// before any message is sent. Catches a client that lies about its
// mode/username in the cleartext header prefix: the cleartext header
// would say one thing and the Noise hash would expect another, so the
// responder's AEAD MAC over the handshake state fails to verify and the
// handshake collapses. Bumping the magic forces old clients to fail
// closed because their prologue stops matching ours.
var vncNoisePrologueMagic = []byte("NetBird/VNC/Noise/v1\x00")

// BuildVNCNoisePrologue returns the deterministic byte sequence both
// sides feed to noise.Config.Prologue for a VNC handshake. Exported so
// the WASM proxy client computes the exact same bytes; any divergence
// makes the handshake fail.
func BuildVNCNoisePrologue(mode byte, username string) []byte {
	out := make([]byte, 0, len(vncNoisePrologueMagic)+1+2+len(username))
	out = append(out, vncNoisePrologueMagic...)
	out = append(out, mode)
	out = append(out, byte(len(username)>>8), byte(len(username)))
	out = append(out, []byte(username)...)
	return out
}

func (s *Server) authenticateSession(header *connectionHeader) (string, error) {
	if !header.identityVerified {
		return "", fmt.Errorf("identity proof missing")
	}
	if len(header.clientStatic) != 32 {
		return "", fmt.Errorf("client static key missing")
	}

	userIDHash, err := s.authorizer.LookupSessionKey(header.clientStatic)
	if err != nil {
		return "", fmt.Errorf("lookup session pubkey: %w", err)
	}

	osUser := "*"
	if header.mode == ModeSession {
		osUser = header.username
	}
	if _, err := s.authorizer.AuthorizeOSUserBySessionKey(userIDHash, osUser); err != nil {
		return "", fmt.Errorf("authorize OS user %q: %w", osUser, err)
	}
	return userIDHash.String(), nil
}

// readConnectionHeader reads the NetBird VNC session header. Format:
//
//	[mode: 1] [username_len: 2 BE] [username: N]
//	[opt magic "NBV3": 4] [noise_msg1: 96]
//	  (server writes [noise_msg2: 48] here when the magic is present)
//	[session_id: 4 BE] [width: 2 BE] [height: 2 BE]
//
// Standard VNC clients don't speak first, so they time out on the first
// read and fall through to attach mode (which auth still rejects when
// no Noise handshake completed).
func (s *Server) readConnectionHeader(conn net.Conn) (*connectionHeader, error) {
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	var hdr [3]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return &connectionHeader{mode: ModeAttach}, nil
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	mode := hdr[0]
	usernameLen := binary.BigEndian.Uint16(hdr[1:3])

	var username string
	if usernameLen > 0 {
		if usernameLen > 256 {
			return nil, fmt.Errorf("username too long: %d", usernameLen)
		}
		buf := make([]byte, usernameLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, fmt.Errorf("read username: %w", err)
		}
		username = string(buf)
	}

	// Read the 4-byte magic candidate directly off the wire instead of
	// buffering ahead with a bufio.Reader: the session reads the raw conn
	// after this returns, so any bytes a bufio.Reader buffered past the
	// header would be silently dropped. When the bytes aren't the v3 magic
	// they are the start of the session_id field and feed straight into it.
	var magicBuf [4]byte
	if _, err := io.ReadFull(conn, magicBuf[:]); err != nil {
		return &connectionHeader{mode: mode, username: username}, nil
	}

	clientStatic, identityVerified, magicConsumed, err := s.maybeRunNoiseHandshake(conn, magicBuf, mode, username)
	if err != nil {
		return nil, err
	}

	var sessionID uint32
	var width, height uint16
	if magicConsumed {
		var sidBuf [4]byte
		if _, err := io.ReadFull(conn, sidBuf[:]); err == nil {
			sessionID = binary.BigEndian.Uint32(sidBuf[:])
		}
	} else {
		// No magic: the 4 bytes we already read are the session_id.
		sessionID = binary.BigEndian.Uint32(magicBuf[:])
	}

	var geomBuf [4]byte
	if _, err := io.ReadFull(conn, geomBuf[:]); err == nil {
		width = binary.BigEndian.Uint16(geomBuf[0:2])
		height = binary.BigEndian.Uint16(geomBuf[2:4])
	}

	return &connectionHeader{
		mode:             mode,
		username:         username,
		clientStatic:     clientStatic,
		sessionID:        sessionID,
		width:            width,
		height:           height,
		identityVerified: identityVerified,
	}, nil
}

// maybeRunNoiseHandshake performs the responder side of a Noise_IK
// handshake when the client sends the v3 magic. Returns the client static
// public key learned from the handshake. Any handshake failure is fatal
// (fail closed). headerMode and headerUsername are mixed into the Noise
// prologue so the client cannot lie in the cleartext header prefix
// without making its own AEAD MAC verify-fail on the responder side.
func (s *Server) maybeRunNoiseHandshake(conn net.Conn, magic [4]byte, headerMode byte, headerUsername string) (clientStatic []byte, identityVerified, magicConsumed bool, err error) {
	if !bytes.Equal(magic[:], vncIdentityMagic) {
		return nil, false, false, nil
	}

	msg1 := make([]byte, noiseInitiatorMsgLen)
	if _, err := io.ReadFull(conn, msg1); err != nil {
		return nil, false, true, fmt.Errorf("read noise msg1: %w", err)
	}

	// Agents on loopback authenticate via the agent token, not this
	// handshake: the daemon already ran Noise on the public side and
	// is now proxying the replayed bytes through to us. Consume the
	// bytes and report identityVerified=false: the agent's own
	// authorizeSession short-circuits on disableAuth and never reaches
	// authenticateSession, so this return value has no effect on the
	// agent's accept path, but a future caller that forgets the
	// short-circuit will see the truthful "no Noise identity proved
	// here" rather than a stale true.
	if s.disableAuth {
		return nil, false, true, nil
	}

	if len(s.identityKey) != 32 || len(s.identityPublic) != 32 {
		return nil, false, true, errors.New("identity key not configured")
	}
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      BuildVNCNoisePrologue(headerMode, headerUsername),
		StaticKeypair: noise.DHKey{Private: s.identityKey, Public: s.identityPublic},
	})
	if err != nil {
		return nil, false, true, fmt.Errorf("noise responder init: %w", err)
	}
	if _, _, _, err := state.ReadMessage(nil, msg1); err != nil {
		return nil, false, true, fmt.Errorf("noise read msg1: %w", err)
	}
	msg2, _, _, err := state.WriteMessage(nil, nil)
	if err != nil {
		return nil, false, true, fmt.Errorf("noise write msg2: %w", err)
	}
	if len(msg2) != noiseResponderMsgLen {
		return nil, false, true, fmt.Errorf("noise responder produced %d bytes, expected %d", len(msg2), noiseResponderMsgLen)
	}
	if _, err := conn.Write(msg2); err != nil {
		return nil, false, true, fmt.Errorf("write noise msg2: %w", err)
	}

	peerStatic := state.PeerStatic()
	if len(peerStatic) != 32 {
		return nil, false, true, errors.New("noise peer static missing")
	}
	return peerStatic, true, true, nil
}

// verifyAgentToken validates the agent token prefix when configured and
// reads the trailing view-only flag byte the daemon writes alongside it.
// Returns (ok, viewOnly). ok=false closes the connection.
func (s *Server) verifyAgentToken(conn net.Conn, connLog *log.Entry) (bool, bool) {
	if len(s.agentToken) == 0 {
		return true, false
	}
	buf := make([]byte, len(s.agentToken)+1)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		connLog.Debugf("set agent token deadline: %v", err)
		conn.Close()
		return false, false
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Connect-then-close probes (port liveness checks) hit this
			// path on every dial; logging them would just flood the
			// daemon log without surfacing a real failure.
			connLog.Tracef("agent auth: read preamble: %v", err)
		} else {
			connLog.Warnf("agent auth: read preamble: %v", err)
		}
		conn.Close()
		return false, false
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		connLog.Debugf("clear agent token deadline: %v", err)
	}
	if subtle.ConstantTimeCompare(buf[:len(s.agentToken)], s.agentToken) != 1 {
		connLog.Warn("agent auth: invalid token, rejecting")
		conn.Close()
		return false, false
	}
	return true, buf[len(s.agentToken)] != 0
}

// authorizeSession runs the Noise_IK handshake when auth is enabled.
// Returns the enriched log entry, user identity hash (empty when auth
// disabled), and ok=false if the connection was rejected.
func (s *Server) authorizeSession(conn net.Conn, header *connectionHeader, connLog *log.Entry) (*log.Entry, string, bool) {
	if s.disableAuth {
		return connLog, "", true
	}
	userID, err := s.authenticateSession(header)
	if err != nil {
		rejectConnection(conn, codeMessage(RejectCodeAuthForbidden, err.Error()))
		connLog.Warnf("auth rejected: %v", err)
		return connLog, "", false
	}
	return connLog.WithFields(log.Fields{
		"session_user": userID,
		"session_key":  sessionKeyFingerprint(header.clientStatic),
	}), userID, true
}

// sessionKeyFingerprint returns a short hex fingerprint of a client
// static key for log correlation. Distinct VNC sessions of the same
// user end up with distinct fingerprints because each session mints a
// fresh keypair, so this lets an operator tell parallel sessions apart.
func sessionKeyFingerprint(clientStatic []byte) string {
	if len(clientStatic) < 4 {
		return ""
	}
	return hex.EncodeToString(clientStatic[:4])
}
