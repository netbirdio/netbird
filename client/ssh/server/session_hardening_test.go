//go:build !js

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

func dialNoAuthServer(t *testing.T, addr string, hostKey []byte) *cryptossh.Client {
	t.Helper()

	clientKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	signer, err := cryptossh.ParsePrivateKey(clientKey)
	require.NoError(t, err)
	hostSigner, err := cryptossh.ParsePrivateKey(hostKey)
	require.NoError(t, err)
	current, err := user.Current()
	require.NoError(t, err)

	client, err := cryptossh.Dial("tcp", addr, &cryptossh.ClientConfig{
		User:            current.Username,
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)},
		HostKeyCallback: cryptossh.FixedHostKey(hostSigner.PublicKey()),
		Timeout:         3 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func startNoAuthServer(t *testing.T) (string, []byte) {
	t.Helper()

	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	srv := New(&Config{HostKeyPEM: hostKey})
	srv.SetAllowRootLogin(true)
	addr := StartTestServer(t, srv)
	t.Cleanup(func() { require.NoError(t, srv.Stop()) })
	return addr, hostKey
}

// ptyReqPayload builds a pty-req payload whose term string claims the given length.
func ptyReqPayload(termLen uint32, term string) []byte {
	buf := make([]byte, 4, 64)
	binary.BigEndian.PutUint32(buf, termLen)
	buf = append(buf, term...)
	buf = append(buf, make([]byte, 16)...)
	return buf
}

// A pty-req with a term length close to the uint32 maximum must be refused and must
// not take the daemon down.
func TestSession_MalformedPtyReqDoesNotCrashServer(t *testing.T) {
	addr, hostKey := startNoAuthServer(t)
	client := dialNoAuthServer(t, addr, hostKey)

	session, err := client.NewSession()
	require.NoError(t, err)

	ok, err := session.SendRequest("pty-req", true, ptyReqPayload(0xFFFFFFFF, "xterm"))
	require.NoError(t, err)
	assert.False(t, ok, "malformed pty-req should be rejected")
	_ = session.Close()

	// The server must still serve a fresh connection.
	again := dialNoAuthServer(t, addr, hostKey)
	s2, err := again.NewSession()
	require.NoError(t, err)
	require.NoError(t, s2.Close())
}

// Env requests past the per-session cap are refused in order, and the ones before it
// are still accepted.
func TestSession_EnvRequestsAreCapped(t *testing.T) {
	addr, hostKey := startNoAuthServer(t)
	client := dialNoAuthServer(t, addr, hostKey)

	session, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	payload := cryptossh.Marshal(struct{ Key, Value string }{"FOO", "bar"})
	accepted := 0
	for i := 0; i < maxEnvRequests+50; i++ {
		ok, err := session.SendRequest("env", true, payload)
		require.NoError(t, err)
		if ok {
			accepted++
		}
	}
	assert.Equal(t, maxEnvRequests, accepted, "only the first maxEnvRequests env requests should be accepted")

	oversized := cryptossh.Marshal(struct{ Key, Value string }{"BIG", string(make([]byte, maxEnvPayload))})
	fresh, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = fresh.Close() })
	ok, err := fresh.SendRequest("env", true, oversized)
	require.NoError(t, err)
	assert.False(t, ok, "an env request over the payload limit should be refused")
}

// A flood of window-change requests before the command starts must not stall the
// session's request loop: the next request still gets its reply.
func TestSession_WindowChangeFloodDoesNotStallRequests(t *testing.T) {
	addr, hostKey := startNoAuthServer(t)
	client := dialNoAuthServer(t, addr, hostKey)

	session, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	require.NoError(t, session.RequestPty("xterm", 24, 80, cryptossh.TerminalModes{}))

	winch := cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 40, 0, 0})
	for i := 0; i < 500; i++ {
		_, err := session.SendRequest("window-change", false, winch)
		require.NoError(t, err)
	}

	done := make(chan bool, 1)
	go func() {
		ok, err := session.SendRequest("env", true, cryptossh.Marshal(struct{ Key, Value string }{"A", "b"}))
		done <- err == nil && ok
	}()
	select {
	case ok := <-done:
		assert.True(t, ok, "env request after the flood should be accepted")
	case <-time.After(5 * time.Second):
		t.Fatal("session request loop stalled behind window-change requests")
	}
}

func TestSession_PerConnectionSessionLimit(t *testing.T) {
	addr, hostKey := startNoAuthServer(t)
	client := dialNoAuthServer(t, addr, hostKey)

	for i := 0; i < maxSessionsPerConn; i++ {
		s, err := client.NewSession()
		require.NoError(t, err, "session %d should open", i)
		t.Cleanup(func() { _ = s.Close() })
	}

	_, err := client.NewSession()
	assert.Error(t, err, "session beyond the limit should be refused")

	// The limit is per connection: another connection is unaffected.
	other := dialNoAuthServer(t, addr, hostKey)
	s, err := other.NewSession()
	require.NoError(t, err, "a second connection should still open sessions")
	require.NoError(t, s.Close())
}

func TestValidPtyReqPayload(t *testing.T) {
	assert.True(t, validPtyReqPayload(ptyReqPayload(5, "xterm")))
	assert.False(t, validPtyReqPayload(nil), "empty payload")
	assert.False(t, validPtyReqPayload([]byte{0, 0, 0}), "short length prefix")
	assert.False(t, validPtyReqPayload(ptyReqPayload(0xFFFFFFFF, "xterm")), "length that wraps uint32")
	assert.False(t, validPtyReqPayload(ptyReqPayload(1000, "xterm")), "length beyond the payload")
}

// A resize sent while the command runs reaches the pty.
func TestSession_ResizeWhileRunningIsApplied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stty is not available")
	}
	addr, hostKey := startNoAuthServer(t)
	client := dialNoAuthServer(t, addr, hostKey)

	session, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	var out bytes.Buffer
	session.Stdout = &out
	require.NoError(t, session.RequestPty("xterm", 24, 80, cryptossh.TerminalModes{}))
	require.NoError(t, session.Start("sleep 1; stty size"))

	// Let the handler read the initial window before resizing.
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, session.WindowChange(50, 132))
	require.NoError(t, session.Wait())
	assert.Equal(t, "50 132", strings.TrimSpace(out.String()), "pty should have the resized dimensions")
}

// Forwarded connections beyond the per-connection cap are refused, and a closed one
// frees its slot.
func TestDirectTCPIP_PerConnectionLimit(t *testing.T) {
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	srv := New(&Config{HostKeyPEM: hostKey})
	srv.SetAllowRootLogin(true)
	srv.SetAllowLocalPortForwarding(true)
	addr := StartTestServer(t, srv)
	t.Cleanup(func() { require.NoError(t, srv.Stop()) })

	// Target that holds each connection open until the peer half-closes, then closes it
	// like a regular server.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}()
		}
	}()

	client := dialNoAuthServer(t, addr, hostKey)

	conns := make([]net.Conn, 0, maxDirectTCPIPPerConn)
	for i := 0; i < maxDirectTCPIPPerConn; i++ {
		c, err := client.Dial("tcp", target.Addr().String())
		require.NoError(t, err, "forward %d should open", i)
		conns = append(conns, c)
	}

	_, err = client.Dial("tcp", target.Addr().String())
	assert.Error(t, err, "forward beyond the limit should be refused")

	// The limit is per connection: another connection is unaffected.
	other := dialNoAuthServer(t, addr, hostKey)
	oc, err := other.Dial("tcp", target.Addr().String())
	require.NoError(t, err, "a second connection should still open forwards")
	require.NoError(t, oc.Close())

	require.NoError(t, conns[0].Close())
	assert.Eventually(t, func() bool {
		c, err := client.Dial("tcp", target.Addr().String())
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 3*time.Second, 50*time.Millisecond, "a closed forward should free its slot")

	for _, c := range conns[1:] {
		_ = c.Close()
	}
}

// A connection that never completes the SSH handshake is dropped, and one that does
// complete it is not subject to the handshake deadline afterwards.
func TestHandshakeTimeout(t *testing.T) {
	hostKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	srv := New(&Config{HostKeyPEM: hostKey})
	srv.handshakeTimeout = 500 * time.Millisecond
	addr := StartTestServer(t, srv)
	t.Cleanup(func() { require.NoError(t, srv.Stop()) })

	stalled, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stalled.Close() })

	// The server sends its version line first; after that it waits for ours.
	require.NoError(t, stalled.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.Copy(io.Discard, stalled)
	var nerr net.Error
	assert.False(t, errors.As(err, &nerr) && nerr.Timeout(), "server should close the stalled connection, not leave it open")

	client := dialNoAuthServer(t, addr, hostKey)
	time.Sleep(time.Second)
	session, err := client.NewSession()
	require.NoError(t, err, "an established connection must outlive the handshake deadline")
	require.NoError(t, session.Close())
}

// Refused requests are forwarded to the session loop under a type it answers with a
// failure, so every reply is sent by the loop in request order.
func TestFilterSessionRequests_RefusedRequestsStayInOrder(t *testing.T) {
	in := make(chan *cryptossh.Request)
	out := filterSessionRequests(nil, in)

	validWinch := cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 40, 0, 0})
	reqs := []*cryptossh.Request{
		{Type: "pty-req", Payload: ptyReqPayload(0xFFFFFFFF, "xterm")},
		{Type: "pty-req", Payload: ptyReqPayload(5, "xterm")},
		{Type: "window-change", Payload: validWinch},
		{Type: "shell"},
		{Type: "window-change", Payload: validWinch},
		{Type: "window-change", Payload: validWinch},
	}
	want := []string{
		refusedRequestType, // malformed pty-req
		"pty-req",
		refusedRequestType, // resize before the command starts
		"shell",
		refusedRequestType, // older of two queued resizes
		"window-change",
	}

	// Hold all requests in the filter's queue before the loop consumes any, so the
	// coalescing of the two trailing resizes is exercised.
	for _, r := range reqs {
		in <- r
	}
	for i, w := range want {
		select {
		case got := <-out:
			assert.Equal(t, w, got.Type, "request %d", i)
		case <-time.After(2 * time.Second):
			t.Fatalf("request %d not delivered", i)
		}
	}

	close(in)
	select {
	case _, ok := <-out:
		assert.False(t, ok, "filter should close its output when the input closes")
	case <-time.After(2 * time.Second):
		t.Fatal("filter did not close its output")
	}
}
