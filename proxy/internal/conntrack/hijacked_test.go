package conntrack

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHijackWriter implements http.ResponseWriter and http.Hijacker for testing.
type fakeHijackWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (f *fakeHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(f.conn), bufio.NewWriter(f.conn))
	return f.conn, rw, nil
}

func TestCloseByHost(t *testing.T) {
	var tracker HijackTracker

	// Simulate hijacking two connections for different hosts.
	connA1, connA2 := net.Pipe()
	defer connA2.Close()
	connB1, connB2 := net.Pipe()
	defer connB2.Close()

	twA := &trackingWriter{
		ResponseWriter: httptest.NewRecorder(),
		tracker:        &tracker,
		host:           "a.example.com",
	}
	twB := &trackingWriter{
		ResponseWriter: httptest.NewRecorder(),
		tracker:        &tracker,
		host:           "b.example.com",
	}

	// Use fakeHijackWriter to provide the Hijack method.
	twA.ResponseWriter = &fakeHijackWriter{ResponseWriter: twA.ResponseWriter, conn: connA1}
	twB.ResponseWriter = &fakeHijackWriter{ResponseWriter: twB.ResponseWriter, conn: connB1}

	_, _, err := twA.Hijack()
	require.NoError(t, err)
	_, _, err = twB.Hijack()
	require.NoError(t, err)

	tracker.mu.Lock()
	assert.Equal(t, 2, len(tracker.conns), "should track 2 connections")
	tracker.mu.Unlock()

	// Close only host A.
	n := tracker.CloseByHost("a.example.com")
	assert.Equal(t, 1, n, "should close 1 connection for host A")

	tracker.mu.Lock()
	assert.Equal(t, 1, len(tracker.conns), "should have 1 remaining connection")
	tracker.mu.Unlock()

	// Verify host A's conn is actually closed.
	buf := make([]byte, 1)
	_, err = connA2.Read(buf)
	assert.Error(t, err, "host A pipe should be closed")

	// Host B should still be alive.
	go func() { _, _ = connB1.Write([]byte("x")) }()

	// Close all remaining.
	n = tracker.CloseAll()
	assert.Equal(t, 1, n, "should close remaining 1 connection")

	tracker.mu.Lock()
	assert.Equal(t, 0, len(tracker.conns), "should have 0 connections after CloseAll")
	tracker.mu.Unlock()
}

func TestCloseAll(t *testing.T) {
	var tracker HijackTracker

	for range 5 {
		c1, c2 := net.Pipe()
		defer c2.Close()
		tc := &trackedConn{Conn: c1, tracker: &tracker, host: "test.com"}
		tracker.add(tc)
	}

	tracker.mu.Lock()
	assert.Equal(t, 5, len(tracker.conns))
	tracker.mu.Unlock()

	n := tracker.CloseAll()
	assert.Equal(t, 5, n)

	// Double CloseAll is safe.
	n = tracker.CloseAll()
	assert.Equal(t, 0, n)
}

func TestTrackedConn_AutoDeregister(t *testing.T) {
	var tracker HijackTracker

	c1, c2 := net.Pipe()
	defer c2.Close()

	tc := &trackedConn{Conn: c1, tracker: &tracker, host: "auto.com"}
	tracker.add(tc)

	tracker.mu.Lock()
	assert.Equal(t, 1, len(tracker.conns))
	tracker.mu.Unlock()

	// Close the tracked conn: should auto-deregister.
	require.NoError(t, tc.Close())

	tracker.mu.Lock()
	assert.Equal(t, 0, len(tracker.conns), "should auto-deregister on close")
	tracker.mu.Unlock()
}

func TestHostOnly(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"[::1]:443", "[::1]"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, hostOnly(tt.input))
		})
	}
}
