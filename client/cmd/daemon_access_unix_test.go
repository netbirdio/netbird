//go:build !windows

package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A socket the caller may not write must fail the dial with the denial, well
// before the dial timeout.
func TestDialClientGRPCServer_SocketRefusesCaller(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket file permissions")
	}
	dir, err := os.MkdirTemp("", "nbdial")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	require.NoError(t, os.Chmod(path, 0o000))

	start := time.Now()
	_, err = DialClientGRPCServer(context.Background(), "unix://"+path)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, errDaemonAccessDenied)
	assert.Less(t, elapsed, 5*time.Second, "a refused socket must not wait out the dial timeout")
	assert.Equal(t, errDaemonAccessDenied, daemonConnectError(err), "the denial is reported without the start-the-service hint")
}

func TestDaemonConnectError_KeepsServiceHintOtherwise(t *testing.T) {
	err := daemonConnectError(errors.New("context deadline exceeded"))
	assert.Contains(t, err.Error(), "netbird service start", "a daemon that did not answer keeps the hint to start it")
}
