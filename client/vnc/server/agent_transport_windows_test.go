//go:build windows

package server

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// testPipeSDDL widens the agent DACL to administrators so a test that does not
// run as SYSTEM can still connect. Creating a pipe in the protected namespace
// needs administrator rights either way.
const testPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

func listenTestPipe(t *testing.T, sddl string) (string, net.Listener) {
	t.Helper()
	path, err := newAgentPipePath(0)
	require.NoError(t, err)
	ln, err := listenAgentPipe(path, sddl)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("creating a pipe under ProtectedPrefix needs administrator rights")
	}
	require.NoError(t, err, "create pipe in the protected namespace")
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return path, ln
}

// The test process serves the pipe itself, so the pipe server PID the daemon
// side reads back is our own PID.
func TestAgentPipePeerPID(t *testing.T) {
	path, _ := listenTestPipe(t, testPipeSDDL)
	self := uint32(os.Getpid())

	require.NoError(t, waitForAgentListening(path, self, 2*time.Second),
		"readiness gate must accept a pipe served by the expected PID")
	assert.Error(t, waitForAgentListening(path, self+1, 2*time.Second),
		"readiness gate must reject a pipe served by another PID")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialAgent(ctx, path)
	require.NoError(t, err)
	defer conn.Close()

	assert.NoError(t, validateAgentPeer(conn, self))
	assert.Error(t, validateAgentPeer(conn, self+1), "mismatched PID must fail")
	assert.Error(t, validateAgentPeer(conn, 0), "unknown PID must fail closed")
}

// The agent's server runs its source check on the accepted pipe connection's
// remote address, so that address must count as local IPC.
func TestAgentPipeRemoteAddrIsAllowedSource(t *testing.T) {
	path, err := newAgentPipePath(0)
	require.NoError(t, err)
	ln, err := listenAgentPipe(path, testPipeSDDL)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("creating a pipe under ProtectedPrefix needs administrator rights")
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := dialAgent(ctx, path)
	require.NoError(t, err)
	defer client.Close()

	server, ok := <-accepted
	require.True(t, ok, "accept must succeed")
	defer server.Close()

	srv := New(Config{Capturer: &testCapturer{}, Injector: &StubInputInjector{}})
	assert.True(t, srv.isAllowedSource(server.RemoteAddr()),
		"pipe remote %T must pass the source check", server.RemoteAddr())
}

// A second listener on the same name must fail, so an agent never serves a
// pipe name some other process created first.
func TestAgentPipeRefusesExistingName(t *testing.T) {
	path, _ := listenTestPipe(t, testPipeSDDL)

	second, err := listenAgentPipe(path, testPipeSDDL)
	if second != nil {
		_ = second.Close()
	}
	assert.Error(t, err, "creating an existing pipe name must fail")
}

// The production DACL admits only LocalSystem, so any other caller, an
// administrator included, is refused.
func TestAgentPipeDeniesNonSystem(t *testing.T) {
	if isLocalSystem(t) {
		t.Skip("running as LocalSystem, which the DACL admits")
	}
	path, _ := listenTestPipe(t, agentPipeSDDL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialAgent(ctx, path)
	if conn != nil {
		_ = conn.Close()
	}
	assert.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
}

func isLocalSystem(t *testing.T) bool {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	require.NoError(t, err)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	return user.User.Sid.Equals(system)
}
