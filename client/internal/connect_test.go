package internal

import (
	"net"
	"testing"
)

func Test_freePort(t *testing.T) {
	// Ports are obtained from the OS instead of hardcoded: a fixed number can
	// fall inside the ephemeral range and be occupied by an unrelated process
	// on the test runner, making the test flaky.
	busy, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("failed to bind busy port: %v", err)
	}
	defer func() {
		_ = busy.Close()
	}()
	busyPort := busy.LocalAddr().(*net.UDPAddr).Port

	free, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("failed to bind free port: %v", err)
	}
	freePortNum := free.LocalAddr().(*net.UDPAddr).Port
	if err := free.Close(); err != nil {
		t.Fatalf("failed to close free port: %v", err)
	}

	tests := []struct {
		name        string
		port        int
		want        int
		shouldMatch bool
	}{
		{
			name:        "when port is 0 use random port",
			port:        0,
			want:        0,
			shouldMatch: false,
		},
		{
			name:        "provided and available",
			port:        freePortNum,
			want:        freePortNum,
			shouldMatch: true,
		},
		{
			name:        "provided and not available",
			port:        busyPort,
			want:        busyPort,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			got, err := freePort(tt.port)

			if err != nil {
				t.Errorf("got an error while getting free port: %v", err)
			}

			if tt.shouldMatch && got != tt.want {
				t.Errorf("got a different port %v, want %v", got, tt.want)
			}

			if !tt.shouldMatch && got == tt.want {
				t.Errorf("got the same port %v, want a different port", tt.want)
			}
		})

	}
}
