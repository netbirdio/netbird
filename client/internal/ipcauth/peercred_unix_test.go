//go:build linux || darwin || freebsd

package ipcauth

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPeerIdentity_MatchesCurrentProcess connects to a real Unix socket and
// verifies the extracted UID/GID match the running process (both ends are us).
func TestPeerIdentity_MatchesCurrentProcess(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		id  Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			done <- result{err: aerr}
			return
		}
		defer func() { _ = c.Close() }()
		id, ierr := PeerIdentity(c)
		done <- result{id: id, err: ierr}
	}()

	client, err := net.Dial("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	res := <-done
	require.NoError(t, res.err)
	assert.Equal(t, uint32(os.Getuid()), res.id.UID, "UID should match current process")
	assert.Equal(t, uint32(os.Getgid()), res.id.GID, "primary GID should match current process")
}

// TestPeerIdentity_NonUnixConn rejects non-Unix connections (fail closed).
func TestPeerIdentity_NonUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			done <- aerr
			return
		}
		defer func() { _ = c.Close() }()
		_, ierr := PeerIdentity(c)
		done <- ierr
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	assert.Error(t, <-done, "PeerIdentity must reject a non-Unix connection")
}

// TestUnixCreds_ServerHandshake exercises the transport-credentials path end to end.
func TestUnixCreds_ServerHandshake(t *testing.T) {
	creds := NewTransportCredentials()
	require.NotNil(t, creds)

	sock := filepath.Join(t.TempDir(), "hs.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		info interface{ AuthType() string }
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			done <- result{err: aerr}
			return
		}
		_, ai, herr := creds.ServerHandshake(c)
		if herr != nil {
			done <- result{err: herr}
			return
		}
		done <- result{info: ai}
	}()

	client, err := net.Dial("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	res := <-done
	require.NoError(t, res.err)
	ai, ok := res.info.(AuthInfo)
	require.True(t, ok, "expected ipcauth.AuthInfo, got %T", res.info)
	assert.Equal(t, uint32(os.Getuid()), ai.Identity.UID)
	assert.Equal(t, "netbird-ipc-peercred", ai.AuthType())
}
