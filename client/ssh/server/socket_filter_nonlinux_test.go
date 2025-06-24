//go:build !linux

package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttachSocketFilter_NonLinux(t *testing.T) {
	// Create a test TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Should resolve TCP address")

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err, "Should create TCP listener")
	defer func() {
		if closeErr := tcpListener.Close(); closeErr != nil {
			t.Logf("TCP listener close error: %v", closeErr)
		}
	}()

	// Test that socket filter attachment returns an error on non-Linux platforms
	err = attachSocketFilter(tcpListener, 1)
	require.Error(t, err, "Should return error on non-Linux platforms")
	require.Contains(t, err.Error(), "only supported on Linux", "Error should indicate platform limitation")
}

func TestDetachSocketFilter_NonLinux(t *testing.T) {
	// Create a test TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Should resolve TCP address")

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err, "Should create TCP listener")
	defer func() {
		if closeErr := tcpListener.Close(); closeErr != nil {
			t.Logf("TCP listener close error: %v", closeErr)
		}
	}()

	// Test that socket filter detachment returns an error on non-Linux platforms
	err = detachSocketFilter(tcpListener)
	require.Error(t, err, "Should return error on non-Linux platforms")
	require.Contains(t, err.Error(), "only supported on Linux", "Error should indicate platform limitation")
}
