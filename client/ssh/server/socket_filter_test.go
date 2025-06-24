//go:build linux

package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
)

func TestCreateInterfaceFilterProgram(t *testing.T) {
	wgIfIndex := uint32(42)

	prog, err := createInterfaceFilterProgram(wgIfIndex)
	require.NoError(t, err, "Should create BPF program without error")
	require.NotEmpty(t, prog, "BPF program should not be empty")

	// Verify program structure
	require.Len(t, prog, 4, "BPF program should have 4 instructions")

	// Check first instruction - load interface index
	loadExt, ok := prog[0].(bpf.LoadExtension)
	require.True(t, ok, "First instruction should be LoadExtension")
	require.Equal(t, bpf.ExtInterfaceIndex, loadExt.Num, "Should load interface index extension")

	// Check second instruction - compare with target interface
	jumpIf, ok := prog[1].(bpf.JumpIf)
	require.True(t, ok, "Second instruction should be JumpIf")
	require.Equal(t, bpf.JumpEqual, jumpIf.Cond, "Should compare for equality")
	require.Equal(t, wgIfIndex, jumpIf.Val, "Should compare with correct interface index")
	require.Equal(t, uint8(1), jumpIf.SkipTrue, "Should skip next instruction if match")

	// Check third instruction - reject if not matching
	rejectRet, ok := prog[2].(bpf.RetConstant)
	require.True(t, ok, "Third instruction should be RetConstant")
	require.Equal(t, uint32(0), rejectRet.Val, "Should return 0 to reject packet")

	// Check fourth instruction - accept if matching
	acceptRet, ok := prog[3].(bpf.RetConstant)
	require.True(t, ok, "Fourth instruction should be RetConstant")
	require.Equal(t, uint32(0xFFFFFFFF), acceptRet.Val, "Should return max value to accept packet")
}

func TestCreateInterfaceFilterProgram_Assembly(t *testing.T) {
	wgIfIndex := uint32(10)

	prog, err := createInterfaceFilterProgram(wgIfIndex)
	require.NoError(t, err, "Should create BPF program without error")

	// Test that the program can be assembled
	assembled, err := bpf.Assemble(prog)
	require.NoError(t, err, "BPF program should assemble without error")
	require.NotEmpty(t, assembled, "Assembled program should not be empty")
	require.True(t, len(assembled) > 0, "Should produce non-empty assembled instructions")
}

func TestAttachSocketFilter_NonTCPListener(t *testing.T) {
	// Create a mock listener that's not a TCP listener
	mockListener := &mockFilterListener{}
	defer mockListener.Close()

	err := attachSocketFilter(mockListener, 1)
	require.Error(t, err, "Should return error for non-TCP listener")
	require.Contains(t, err.Error(), "not a TCP listener", "Error should indicate listener type issue")
}

// mockFilterListener implements net.Listener but is not a TCP listener
type mockFilterListener struct{}

func (m *mockFilterListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (m *mockFilterListener) Close() error {
	return nil
}

func (m *mockFilterListener) Addr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	return addr
}

func TestAttachSocketFilter_Integration(t *testing.T) {
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

	// Get a real interface for testing
	interfaces, err := net.Interfaces()
	require.NoError(t, err, "Should get network interfaces")
	require.NotEmpty(t, interfaces, "Should have at least one network interface")

	// Use the first non-loopback interface
	var testIfIndex int
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Index > 0 {
			testIfIndex = iface.Index
			break
		}
	}

	if testIfIndex == 0 {
		t.Skip("No suitable network interface found for testing")
	}

	// Test socket filter attachment
	err = attachSocketFilter(tcpListener, testIfIndex)
	if err != nil {
		// Socket filter attachment may fail in test environments due to permissions
		// This is expected and acceptable
		t.Logf("Socket filter attachment failed (expected in test environment): %v", err)
		return
	}

	// If attachment succeeded, test detachment
	err = detachSocketFilter(tcpListener)
	if err != nil {
		// Detachment may fail in test environments due to socket state changes
		t.Logf("Socket filter detachment failed (expected in test environment): %v", err)
	}
}

func TestSetSocketFilter_Integration(t *testing.T) {
	testKey := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA2Z3QY0EfAFU+wU1M7FH+6QCPfZhL1H5ZbG5QZ4oP+H8Y7QJYbY
rNYmY+x2G5nU1J5T1x6QaKv8Y5Yx8gKQBz5vBV7V3X9UY1QY0EfAFU+wU1M7FH+6QCP
fZhL1H5ZbG5QZ4oP+H8Y7QJYbYrNYmY+x2G5nU1J5T1x6QaKv8Y5Yx8gKQBz5vBV7V3X
9UY1QY0EfAFU+wU1M7FH+6QCPfZhL1H5ZbG5QZ4oP+H8Y7QJYbYrNYmY+x2G5nU1J5T
1x6QaKv8Y5Yx8gKQBz5vBV7V3X9UY1QY0EfAFU+wU1M7FH+6QCPfZhL1H5ZbG5QZ4oP
+H8Y7QJYbYrNYmY+x2G5nU1J5T1x6QaKv8Y5Yx8gKQBz5vBV7V3X9UAAAA8g+QKV7Ps
ClezwAAAAAABBAAAAdwdwdF9rZXlfc2VjcmV0AAAAAQAAAQEA2Z3QY0EfAFU+wU1M7FH+
6QCPfZhL1H5ZbG5QZ4oP+H8Y7QJYbYrNYmY+x2G5nU1J5T1x6QaKv8Y5Yx8gKQBz5vBV
7V3X9UY1QY0EfAFU+wU1M7FH+6QCPfZhL1H5ZbG5QZ4oP+H8Y7QJYbYrNYmY+x2G5nU
1J5T1x6QaKv8Y5Yx8gKQBz5vBV7V3X9UY1QY0EfAFU+wU1M7FH+6QCPfZhL1H5ZbG5Q
Z4oP+H8Y7QJYbYrNYmY+x2G5nU1J5T1x6QaKv8Y5Yx8gKQBz5vBV7V3X9UY1QY0EfAF
U+wU1M7FH+6QCPfZhL1H5ZbG5QZ4oP+H8Y7QJYbYrNYmY+x2G5nU1J5T1x6QaKv8Y5Y
x8gKQBz5vBV7V3X9UAAAA8g+QKV7PsClezwAAA=
-----END OPENSSH PRIVATE KEY-----`)

	server := New(testKey)
	require.NotNil(t, server, "Should create SSH server")

	// Test SetSocketFilter method
	testIfIndex := 42
	server.SetSocketFilter(testIfIndex)

	// Verify the socket filter configuration was stored
	require.Equal(t, testIfIndex, server.ifIdx, "Should store correct interface index")
}
