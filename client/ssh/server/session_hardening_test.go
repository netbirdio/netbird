//go:build !js

package server

import (
	"bytes"
	"encoding/binary"
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
