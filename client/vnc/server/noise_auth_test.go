//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	sshauth "github.com/netbirdio/netbird/shared/sessionauth"
	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
)

// noiseTestServer starts a VNC server with a freshly generated identity
// key and returns the listener address, the server, and the server's
// static public key for client-side handshake setup.
func noiseTestServer(t *testing.T) (net.Addr, *Server, []byte) {
	t.Helper()

	kp, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	srv := New(Config{
		Capturer:    &testCapturer{},
		Injector:    &StubInputInjector{},
		IdentityKey: kp.Private,
	})

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	return srv.listener.Addr(), srv, kp.Public
}

// registerSessionKey enrolls a fresh X25519 keypair under the given user
// ID into the server's authorizer with the requested OS-user wildcard
// mapping. Returns the keypair so the test can drive the handshake.
func registerSessionKey(t *testing.T, srv *Server, userID string) noise.DHKey {
	t.Helper()

	kp, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	userHash, err := sshuserhash.HashUserID(userID)
	require.NoError(t, err)

	srv.UpdateVNCAuth(&sshauth.Config{
		AuthorizedUsers: []sshuserhash.UserIDHash{userHash},
		MachineUsers:    map[string][]uint32{sshauth.Wildcard: {0}},
		SessionPubKeys: []sshauth.SessionPubKey{
			{PubKey: kp.Public, UserIDHash: userHash},
		},
	})
	return kp
}

// writeHeaderPrefix writes the mode + (optional) username prefix that
// precedes the optional Noise handshake in the NetBird VNC header.
func writeHeaderPrefix(t *testing.T, conn net.Conn, mode byte) {
	t.Helper()
	writeHeaderPrefixWithUser(t, conn, mode, "")
}

// writeHeaderPrefixWithUser is the username-aware variant used by tests
// that need to verify the Noise prologue binds to the cleartext header.
func writeHeaderPrefixWithUser(t *testing.T, conn net.Conn, mode byte, username string) {
	t.Helper()
	if len(username) > 0xFFFF {
		t.Fatalf("test username too long: %d", len(username))
	}
	prefix := []byte{mode, byte(len(username) >> 8), byte(len(username))}
	prefix = append(prefix, []byte(username)...)
	_, err := conn.Write(prefix)
	require.NoError(t, err)
}

// writeHeaderTail writes the sessionID/width/height fields that follow
// either the Noise msg2 (auth path) or the prefix alone (no-auth path).
func writeHeaderTail(t *testing.T, conn net.Conn) {
	t.Helper()
	tail := make([]byte, 8)
	_, err := conn.Write(tail)
	require.NoError(t, err)
}

// performInitiator drives the initiator side of Noise_IK against the
// server's identity public key, returns the resulting state. The Noise
// msg2 produced by the server is read and consumed. headerMode and
// headerUsername are mixed into the prologue and MUST match what the
// caller already wrote in the cleartext header prefix.
func performInitiator(t *testing.T, conn net.Conn, clientKey noise.DHKey, serverPub []byte) {
	t.Helper()
	performInitiatorWithHeader(t, conn, clientKey, serverPub, ModeAttach, "")
}

func performInitiatorWithHeader(t *testing.T, conn net.Conn, clientKey noise.DHKey, serverPub []byte, headerMode byte, headerUsername string) {
	t.Helper()

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      BuildVNCNoisePrologue(headerMode, headerUsername),
		StaticKeypair: clientKey,
		PeerStatic:    serverPub,
	})
	require.NoError(t, err)

	msg1, _, _, err := state.WriteMessage(nil, nil)
	require.NoError(t, err)
	require.Equal(t, noiseInitiatorMsgLen, len(msg1))

	_, err = conn.Write(append([]byte("NBV3"), msg1...))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	msg2 := make([]byte, noiseResponderMsgLen)
	_, err = io.ReadFull(conn, msg2)
	require.NoError(t, err)
	_, _, _, err = state.ReadMessage(nil, msg2)
	require.NoError(t, err, "server responder message must decrypt with the correct peer static")
}

// readRFBFailure consumes the RFB version exchange and returns the
// security-failure reason string. Fails the test if the server did not
// send a failure (i.e. produced a non-zero security-types list).
func readRFBFailure(t *testing.T, conn net.Conn) string {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	var ver [12]byte
	_, err := io.ReadFull(conn, ver[:])
	require.NoError(t, err)
	require.Equal(t, "RFB 003.008\n", string(ver[:]))

	_, err = conn.Write(ver[:])
	require.NoError(t, err)

	var n [1]byte
	_, err = io.ReadFull(conn, n[:])
	require.NoError(t, err)
	require.Equal(t, byte(0), n[0], "expected security-failure (0 types)")

	var rl [4]byte
	_, err = io.ReadFull(conn, rl[:])
	require.NoError(t, err)
	reason := make([]byte, binary.BigEndian.Uint32(rl[:]))
	_, err = io.ReadFull(conn, reason)
	require.NoError(t, err)
	return string(reason)
}

// readRFBGreetingNoFailure asserts the server proceeded past auth: it
// must offer at least one security type rather than a 0 failure.
func readRFBGreetingNoFailure(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	var ver [12]byte
	_, err := io.ReadFull(conn, ver[:])
	require.NoError(t, err)
	require.Equal(t, "RFB 003.008\n", string(ver[:]))

	_, err = conn.Write(ver[:])
	require.NoError(t, err)

	var n [1]byte
	_, err = io.ReadFull(conn, n[:])
	require.NoError(t, err)
	require.NotEqual(t, byte(0), n[0], "server must offer security types after a valid handshake")
}

// TestNoise_RegisteredKey_AccessGranted exercises the happy path: a
// session key enrolled in the authorizer completes a Noise_IK handshake
// and the server proceeds to the RFB greeting.
func TestNoise_RegisteredKey_AccessGranted(t *testing.T) {
	addr, srv, serverPub := noiseTestServer(t)
	clientKey := registerSessionKey(t, srv, "alice@example")

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)
	performInitiator(t, conn, clientKey, serverPub)
	writeHeaderTail(t, conn)

	readRFBGreetingNoFailure(t, conn)
}

// TestNoise_UnregisteredClientStatic_Rejected proves the authorizer is
// consulted: a syntactically-valid handshake from a key the server has
// never been told about must be rejected fail-closed.
func TestNoise_UnregisteredClientStatic_Rejected(t *testing.T) {
	addr, _, serverPub := noiseTestServer(t)
	// Auth is enabled but the authorizer was not updated, so the lookup
	// path returns ErrSessionKeyNotKnown.
	attackerKey, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)
	performInitiator(t, conn, attackerKey, serverPub)
	writeHeaderTail(t, conn)

	reason := readRFBFailure(t, conn)
	assert.Contains(t, reason, RejectCodeAuthForbidden)
	assert.Contains(t, reason, "session pubkey not registered")
}

// TestNoise_WrongServerStatic_HandshakeFails proves the server's
// identity is bound into the handshake: an initiator using the wrong
// peer static encrypts msg1 under keys the real server can't derive, so
// the server fails the handshake and closes without RFB output.
func TestNoise_WrongServerStatic_HandshakeFails(t *testing.T) {
	addr, srv, _ := noiseTestServer(t)
	clientKey := registerSessionKey(t, srv, "alice@example")

	bogusServerKey, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      BuildVNCNoisePrologue(ModeAttach, ""),
		StaticKeypair: clientKey,
		PeerStatic:    bogusServerKey.Public,
	})
	require.NoError(t, err)
	msg1, _, _, err := state.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, err = conn.Write(append([]byte("NBV3"), msg1...))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var b [1]byte
	_, err = io.ReadFull(conn, b[:])
	require.Error(t, err, "server must close without RFB greeting when msg1 is sealed for a different server identity")
}

// TestNoise_MalformedMsg1_ClosesConnection covers the case where the
// magic prefix is correct but the following 96 bytes are random: the
// noise library fails ReadMessage and the server closes silently.
func TestNoise_MalformedMsg1_ClosesConnection(t *testing.T) {
	addr, _, _ := noiseTestServer(t)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)
	junk := make([]byte, noiseInitiatorMsgLen)
	for i := range junk {
		junk[i] = byte(i)
	}
	_, err = conn.Write(append([]byte("NBV3"), junk...))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var b [1]byte
	_, err = io.ReadFull(conn, b[:])
	require.Error(t, err, "garbage msg1 must terminate the connection before any RFB output")
}

// TestNoise_TruncatedMsg1_ClosesConnection sends fewer than the 96
// bytes a Noise_IK msg1 must contain. The server's io.ReadFull short-
// reads and closes; no RFB greeting must leak.
func TestNoise_TruncatedMsg1_ClosesConnection(t *testing.T) {
	addr, _, _ := noiseTestServer(t)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)
	_, err = conn.Write([]byte("NBV3"))
	require.NoError(t, err)
	_, err = conn.Write(make([]byte, 8))
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.Equal(t, 0, n, "server must not emit RFB bytes after a truncated handshake")
	require.ErrorIs(t, err, io.EOF, "server must close the connection on truncated msg1")
}

// TestNoise_AuthEnabled_NoHandshake_Rejected proves that with auth on,
// a connection that skips the Noise prefix (older client / VNC client)
// is rejected with AUTH_FORBIDDEN: identity proof missing.
func TestNoise_AuthEnabled_NoHandshake_Rejected(t *testing.T) {
	addr, _, _ := noiseTestServer(t)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)
	writeHeaderTail(t, conn)

	reason := readRFBFailure(t, conn)
	assert.Contains(t, reason, RejectCodeAuthForbidden)
	assert.Contains(t, reason, "identity proof missing")
}

// TestNoise_RevokedKey_RejectedAfterAuthUpdate verifies the authorizer
// honors revocations: a key that worked before a UpdateVNCAuth call
// must stop working as soon as the new config omits it.
func TestNoise_RevokedKey_RejectedAfterAuthUpdate(t *testing.T) {
	addr, srv, serverPub := noiseTestServer(t)
	clientKey := registerSessionKey(t, srv, "alice@example")

	// First connection succeeds.
	conn1, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn1.Close()
	writeHeaderPrefix(t, conn1, ModeAttach)
	performInitiator(t, conn1, clientKey, serverPub)
	writeHeaderTail(t, conn1)
	readRFBGreetingNoFailure(t, conn1)

	// Revoke by pushing a fresh config that drops the pubkey entry.
	srv.UpdateVNCAuth(&sshauth.Config{})

	// Same client, same Noise key, should now be denied.
	conn2, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn2.Close()
	writeHeaderPrefix(t, conn2, ModeAttach)
	performInitiator(t, conn2, clientKey, serverPub)
	writeHeaderTail(t, conn2)

	reason := readRFBFailure(t, conn2)
	assert.Contains(t, reason, RejectCodeAuthForbidden)
	assert.Contains(t, reason, "session pubkey not registered")
}

// TestNoise_NoIdentityKey_FailsClosed ensures a server constructed
// without a static private key still rejects authenticated connections
// fail-closed; it must not silently accept the client.
func TestNoise_NoIdentityKey_FailsClosed(t *testing.T) {
	srv := New(Config{Capturer: &testCapturer{}, Injector: &StubInputInjector{}})
	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	clientKey, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	fakeServerKey, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefix(t, conn, ModeAttach)

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      BuildVNCNoisePrologue(ModeAttach, ""),
		StaticKeypair: clientKey,
		PeerStatic:    fakeServerKey.Public,
	})
	require.NoError(t, err)
	msg1, _, _, err := state.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, err = conn.Write(append([]byte("NBV3"), msg1...))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var b [1]byte
	_, err = io.ReadFull(conn, b[:])
	require.Error(t, err, "server without identity key must not write the RFB greeting")
}

// TestNoise_DerivedIdentityPublicMatchesPrivate sanity-checks the
// derivation done in New(): the identityPublic must be Curve25519.
// Basepoint multiplied with identityKey.
func TestNoise_DerivedIdentityPublicMatchesPrivate(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	srv := New(Config{Capturer: &testCapturer{}, Injector: &StubInputInjector{}, IdentityKey: priv})

	expected, err := curve25519.X25519(priv, curve25519.Basepoint)
	require.NoError(t, err)
	assert.Equal(t, expected, srv.identityPublic)
}

// TestNoise_SessionMode_OSUserCheckRunsAfterHandshake verifies that a
// successful Noise handshake doesn't bypass OS-user authorization: an
// authenticated key whose user index isn't mapped to the requested OS
// user must be rejected.
func TestNoise_SessionMode_OSUserCheckRunsAfterHandshake(t *testing.T) {
	addr, srv, serverPub := noiseTestServer(t)

	clientKey, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	userHash, err := sshuserhash.HashUserID("alice@example")
	require.NoError(t, err)

	// Map Alice only to "alice" OS user, not the wildcard.
	srv.UpdateVNCAuth(&sshauth.Config{
		AuthorizedUsers: []sshuserhash.UserIDHash{userHash},
		MachineUsers:    map[string][]uint32{"alice": {0}},
		SessionPubKeys: []sshauth.SessionPubKey{
			{PubKey: clientKey.Public, UserIDHash: userHash},
		},
	})

	// Request session for "bob": Noise succeeds, OS-user check denies.
	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	bob := "bob"
	writeHeaderPrefixWithUser(t, conn, ModeSession, bob)

	performInitiatorWithHeader(t, conn, clientKey, serverPub, ModeSession, bob)
	writeHeaderTail(t, conn)

	reason := readRFBFailure(t, conn)
	assert.Contains(t, reason, RejectCodeAuthForbidden)
	assert.Contains(t, reason, "authorize OS user")
}
