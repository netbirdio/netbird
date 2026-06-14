//go:build !js && !ios && !android

package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"image"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCapturer returns a 100x100 image for test sessions.
type testCapturer struct{}

func (t *testCapturer) Width() int  { return 100 }
func (t *testCapturer) Height() int { return 100 }
func (t *testCapturer) Capture() (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 100, 100)), nil
}

func startTestServer(t *testing.T, disableAuth bool) (net.Addr, *Server) {
	t.Helper()

	srv := New(Config{
		Capturer:    &testCapturer{},
		Injector:    &StubInputInjector{},
		DisableAuth: disableAuth,
	})

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	// Override local address so source validation doesn't reject 127.0.0.1 as "own IP".
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	return srv.listener.Addr(), srv
}

func TestAuthEnabled_NoSessionAuth_RejectsConnection(t *testing.T) {
	addr, _ := startTestServer(t, false)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Header with no Noise handshake. Auth-required servers must reject
	// because no client static was authenticated.
	header := make([]byte, 11) // mode + usernameLen + sessionID + w + h
	header[0] = ModeAttach
	_, err = conn.Write(header)
	require.NoError(t, err)

	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err)
	assert.Equal(t, "RFB 003.008\n", string(version[:]))

	_, err = conn.Write(version[:])
	require.NoError(t, err)

	var numTypes [1]byte
	_, err = io.ReadFull(conn, numTypes[:])
	require.NoError(t, err)
	assert.Equal(t, byte(0), numTypes[0], "should have 0 security types (failure)")

	var reasonLen [4]byte
	_, err = io.ReadFull(conn, reasonLen[:])
	require.NoError(t, err)

	reason := make([]byte, binary.BigEndian.Uint32(reasonLen[:]))
	_, err = io.ReadFull(conn, reason)
	require.NoError(t, err)
	assert.Contains(t, string(reason), "identity proof missing", "rejection reason should mention missing identity proof")
}

func TestAuthDisabled_AllowsConnection(t *testing.T) {
	addr, _ := startTestServer(t, true)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	header := make([]byte, 11) // mode + usernameLen + sessionID + w + h
	header[0] = ModeAttach
	_, err = conn.Write(header)
	require.NoError(t, err)

	// Server should send RFB version.
	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err)
	assert.Equal(t, "RFB 003.008\n", string(version[:]))

	// Write client version.
	_, err = conn.Write(version[:])
	require.NoError(t, err)

	// Should get security types (not 0 = failure).
	var numTypes [1]byte
	_, err = io.ReadFull(conn, numTypes[:])
	require.NoError(t, err)
	assert.NotEqual(t, byte(0), numTypes[0], "should have at least one security type (auth disabled)")
}

// TestAuth_NoUnauthBytesPastHeader proves the server does not send any RFB
// content to a connection that fails source validation. Specifically, the
// server must close immediately and the client must see EOF before any RFB
// version greeting is written.
func TestAuth_NoUnauthBytesPastHeader(t *testing.T) {
	srv := New(Config{
		Capturer:    &testCapturer{},
		Injector:    &StubInputInjector{},
		DisableAuth: true,
	})
	addr := netip.MustParseAddrPort("127.0.0.1:0")
	// Tight overlay that excludes 127.0.0.0/8 and a non-loopback local IP, so
	// the loopback short-circuit in isAllowedSource doesn't apply.
	require.NoError(t, srv.Start(t.Context(), addr, netip.MustParsePrefix("10.99.0.0/16")))
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	// Reading even one byte must EOF: the source IP (127.0.0.1) is outside
	// the configured overlay, so handleConnection closes before writing.
	var b [1]byte
	_, err = io.ReadFull(conn, b[:])
	require.Error(t, err, "non-overlay client must see EOF, not an RFB greeting")
}

func TestIsAllowedSource(t *testing.T) {
	tests := []struct {
		name      string
		localAddr netip.Addr
		network   netip.Prefix
		remote    net.Addr
		want      bool
	}{
		{
			// Unix-domain remotes (per-session agent path) are local IPC,
			// gated by the token, not by overlay membership.
			name:      "non-tcp address allowed",
			localAddr: netip.MustParseAddr("10.99.99.1"),
			network:   netip.MustParsePrefix("10.99.0.0/16"),
			remote:    &net.UnixAddr{Name: "/tmp/foo.sock", Net: "unix"},
			want:      true,
		},
		{
			name:      "own IP rejected",
			localAddr: netip.MustParseAddr("10.99.99.1"),
			network:   netip.MustParsePrefix("10.99.0.0/16"),
			remote:    &net.TCPAddr{IP: net.ParseIP("10.99.99.1"), Port: 5900},
			want:      false,
		},
		{
			name:      "non-overlay IP rejected",
			localAddr: netip.MustParseAddr("10.99.99.1"),
			network:   netip.MustParsePrefix("10.99.0.0/16"),
			remote:    &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5900},
			want:      false,
		},
		{
			name:      "overlay IP allowed",
			localAddr: netip.MustParseAddr("10.99.99.1"),
			network:   netip.MustParsePrefix("10.99.0.0/16"),
			remote:    &net.TCPAddr{IP: net.ParseIP("10.99.99.2"), Port: 5900},
			want:      true,
		},
		{
			name:      "v4-mapped v6 in overlay allowed (unmapped)",
			localAddr: netip.MustParseAddr("10.99.99.1"),
			network:   netip.MustParsePrefix("10.99.0.0/16"),
			remote:    &net.TCPAddr{IP: net.ParseIP("::ffff:10.99.99.2"), Port: 5900},
			want:      true,
		},
		{
			name:      "loopback allowed only when local is loopback",
			localAddr: netip.MustParseAddr("127.0.0.1"),
			network:   netip.MustParsePrefix("127.0.0.0/8"),
			remote:    &net.TCPAddr{IP: net.ParseIP("127.0.0.5"), Port: 5900},
			want:      true,
		},
		{
			name:      "invalid network rejected (fail-closed)",
			localAddr: netip.MustParseAddr("10.99.99.1"),
			network:   netip.Prefix{},
			remote:    &net.TCPAddr{IP: net.ParseIP("10.99.99.2"), Port: 5900},
			want:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(Config{Capturer: &testCapturer{}, Injector: &StubInputInjector{}})
			srv.localAddr = tc.localAddr
			srv.network = tc.network
			assert.Equal(t, tc.want, srv.isAllowedSource(tc.remote))
		})
	}
}

func TestStart_InvalidNetworkRejected(t *testing.T) {
	srv := New(Config{Capturer: &testCapturer{}, Injector: &StubInputInjector{}})
	addr := netip.MustParseAddrPort("127.0.0.1:0")
	err := srv.Start(t.Context(), addr, netip.Prefix{})
	require.Error(t, err, "Start must refuse an invalid overlay prefix")
	assert.Contains(t, err.Error(), "invalid overlay network prefix")
}

func TestAgentToken_MismatchClosesConnection(t *testing.T) {
	srv := New(Config{
		Capturer:      &testCapturer{},
		Injector:      &StubInputInjector{},
		DisableAuth:   true,
		AgentTokenHex: "deadbeefcafebabe",
	})

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	// Send a wrong token of the right length (8 bytes hex-decoded).
	if _, err := conn.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err != nil {
		// Server may already have closed; either way the read below must EOF.
		_ = err
	}

	// Server must close without sending the RFB greeting.
	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.Error(t, err, "server must close the connection on bad agent token")
}

func TestAgentToken_MatchAllowsHandshake(t *testing.T) {
	const tokenHex = "deadbeefcafebabe"
	srv := New(Config{
		Capturer:      &testCapturer{},
		Injector:      &StubInputInjector{},
		DisableAuth:   true,
		AgentTokenHex: tokenHex,
	})
	token, err := hex.DecodeString(tokenHex)
	require.NoError(t, err)

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = conn.Write(token)
	require.NoError(t, err)

	// Send session header so handleConnection can proceed past readConnectionHeader.
	header := make([]byte, 11) // ModeAttach + usernameLen=0 + sessionID=0 + width=0 + height=0
	header[0] = ModeAttach
	_, err = conn.Write(header)
	require.NoError(t, err)

	// With a matching token the server proceeds to the RFB greeting.
	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err, "server must keep the connection open after a valid agent token")
	assert.Equal(t, "RFB 003.008\n", string(version[:]))
}

func TestSessionMode_RejectedWhenNoVMGR(t *testing.T) {
	// Default platformSessionManager() on non-Linux returns nil, so ModeSession
	// must be rejected with the UNSUPPORTED reason rather than crashing.
	srv := New(Config{
		Capturer:    &testCapturer{},
		Injector:    &StubInputInjector{},
		DisableAuth: true,
	})

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	// Force vmgr to nil regardless of platform so the test is deterministic.
	srv.vmgr = nil
	t.Cleanup(func() { _ = srv.Stop() })

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	// ModeSession with no username, so we exit on the vmgr==nil branch
	// before username validation runs.
	header := []byte{ModeSession, 0, 0, 0, 0}
	_, err = conn.Write(header)
	require.NoError(t, err)

	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err)
	_, err = conn.Write(version[:])
	require.NoError(t, err)

	var numTypes [1]byte
	_, err = io.ReadFull(conn, numTypes[:])
	require.NoError(t, err)
	assert.Equal(t, byte(0), numTypes[0])

	var reasonLen [4]byte
	_, err = io.ReadFull(conn, reasonLen[:])
	require.NoError(t, err)
	reason := make([]byte, binary.BigEndian.Uint32(reasonLen[:]))
	_, err = io.ReadFull(conn, reason)
	require.NoError(t, err)
	assert.Contains(t, string(reason), RejectCodeUnsupportedOS)
}

// recordingApprover lets gate tests choose the outcome of the approval
// prompt and verify how often (and with what info) the gate calls it.
type recordingApprover struct {
	calls    atomic.Int32
	lastIn   ApprovalInfo
	decision ApprovalDecision
	respond  error
}

func (r *recordingApprover) Request(_ context.Context, info ApprovalInfo) (ApprovalDecision, error) {
	r.calls.Add(1)
	r.lastIn = info
	if r.respond != nil {
		return ApprovalDecision{}, r.respond
	}
	return r.decision, nil
}

// drainRejectClient simulates a remote VNC client just enough that
// rejectConnection's handshake-half completes promptly: it reads the
// server's "RFB 003.008\n", writes back a placeholder client version, and
// drains until EOF. Without this the rejectConnection path would block
// for up to two seconds on its SetReadDeadline.
func drainRejectClient(t *testing.T, c net.Conn) {
	t.Helper()
	go func() {
		defer c.Close()
		var srvVer [12]byte
		if _, err := io.ReadFull(c, srvVer[:]); err != nil {
			return
		}
		_, _ = c.Write([]byte("RFB 003.008\n"))
		_, _ = io.Copy(io.Discard, c)
	}()
}

// newGateConn returns a server-side conn and a client-side conn linked by
// net.Pipe, with the client-side already draining so gateApproval's
// rejectConnection path completes without blocking the test.
func newGateConn(t *testing.T) net.Conn {
	t.Helper()
	srv, cli := net.Pipe()
	drainRejectClient(t, cli)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func gateTestServer(requireApproval bool, approver Approver) *Server {
	return &Server{
		log:             log.WithField("test", "gate"),
		requireApproval: requireApproval,
		approver:        approver,
	}
}

// TestGateApproval_Disabled_NoApproverCall: when the feature is off the
// gate must short-circuit before consulting any approver. A nil approver
// must NOT mean "deny" here — that would break upgrades for peers that
// haven't opted in yet.
func TestGateApproval_Disabled_NoApproverCall(t *testing.T) {
	app := &recordingApprover{}
	srv := gateTestServer(false, app)

	conn := newGateConn(t)
	defer conn.Close()
	header := &connectionHeader{mode: ModeAttach}

	_, err := srv.gateApproval(conn, header)
	allowed := err == nil
	assert.True(t, allowed, "gate must pass through when requireApproval is false")
	assert.Equal(t, int32(0), app.calls.Load(), "approver must not be called when disabled")
}

// TestGateApproval_Enabled_NilApproverDenies is the most important
// regression test for "no silent bypass": if the feature is enabled but
// the broker wasn't wired (a misconfiguration), the gate must REJECT,
// not pass through. The reject code must be the dedicated NO_APPROVER so
// the failure is unambiguous in logs and on the client side.
func TestGateApproval_Enabled_NilApproverDenies(t *testing.T) {
	srv := gateTestServer(true, nil)

	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	// Capture the reject reason the gate sends.
	rejectReason := make(chan string, 1)
	go func() {
		var srvVer [12]byte
		_, _ = io.ReadFull(cliConn, srvVer[:])
		_, _ = cliConn.Write([]byte("RFB 003.008\n"))
		// Server sends: 1 byte (numTypes=0), 4 bytes (reason len), reason.
		var numTypes [1]byte
		_, _ = io.ReadFull(cliConn, numTypes[:])
		var lenBuf [4]byte
		_, _ = io.ReadFull(cliConn, lenBuf[:])
		reason := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
		_, _ = io.ReadFull(cliConn, reason)
		rejectReason <- string(reason)
	}()

	header := &connectionHeader{mode: ModeAttach}
	_, err := srv.gateApproval(srvConn, header)
	allowed := err == nil
	assert.False(t, allowed, "missing approver MUST deny; never silently pass")

	select {
	case reason := <-rejectReason:
		assert.Contains(t, reason, RejectCodeNoApprover, "reject code must surface the misconfiguration cause")
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe rejection reason")
	}
}

// TestGateApproval_ApproverDenies maps every approver error to a deny.
// We assert against every Err* the broker can produce so a future caller
// adding a new error doesn't accidentally fall into a default-allow.
func TestGateApproval_ApproverDenies(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"denied", errors.New("user denied")},
		{"timeout", errors.New("approval timed out")},
		{"no_subscriber", errors.New("no UI subscriber connected for approval")},
		{"ctx_canceled", context.Canceled},
		{"misc", errors.New("anything else")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &recordingApprover{respond: tc.err}
			srv := gateTestServer(true, app)
			conn := newGateConn(t)
			defer conn.Close()

			header := &connectionHeader{mode: ModeAttach}
			_, err := srv.gateApproval(conn, header)
			allowed := err == nil
			assert.False(t, allowed, "approver error %v must deny", tc.err)
			assert.Equal(t, int32(1), app.calls.Load())
		})
	}
}

// TestGateApproval_ApproverAccepts confirms the happy path actually
// returns true so we know the deny path is not the only outcome the
// gate can produce.
func TestGateApproval_ApproverAccepts(t *testing.T) {
	app := &recordingApprover{respond: nil}
	srv := gateTestServer(true, app)
	conn := newGateConn(t)
	defer conn.Close()

	header := &connectionHeader{mode: ModeAttach, username: "alice"}
	_, err := srv.gateApproval(conn, header)
	allowed := err == nil
	assert.True(t, allowed, "approver returning nil must let the gate pass")
	assert.Equal(t, int32(1), app.calls.Load())
	assert.Equal(t, "alice", app.lastIn.Username, "header username must reach the approver")
}

// TestGateApproval_PassesPubKeyHex confirms the gate hex-encodes the
// 32-byte client static key into ApprovalInfo.PeerPubKey so the prompt's
// metadata identifies which peer is connecting. A wrong-length key must
// NOT bypass the gate; it just won't populate the field.
func TestGateApproval_PassesPubKeyHex(t *testing.T) {
	app := &recordingApprover{respond: nil}
	srv := gateTestServer(true, app)
	conn := newGateConn(t)
	defer conn.Close()

	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	header := &connectionHeader{mode: ModeAttach, clientStatic: pub}
	_, err := srv.gateApproval(conn, header)
	allowed := err == nil
	assert.True(t, allowed)
	assert.Equal(t, hex.EncodeToString(pub), app.lastIn.PeerPubKey)
}
