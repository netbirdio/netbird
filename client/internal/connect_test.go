package internal

import (
	"net"
	"testing"
)

func Test_freePort(t *testing.T) {
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
			port:        51821,
			want:        51821,
			shouldMatch: true,
		},
		{
			name:        "provided and not available",
			port:        51830,
			want:        51830,
			shouldMatch: false,
		},
	}
	c1, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Errorf("freePort error = %v", err)
	}
	defer func(c1 *net.UDPConn) {
		_ = c1.Close()
	}(c1)

	if tests[1].port == c1.LocalAddr().(*net.UDPAddr).Port {
		tests[1].port++
		tests[1].want++
	}

	tests[2].port = c1.LocalAddr().(*net.UDPAddr).Port
	tests[2].want = c1.LocalAddr().(*net.UDPAddr).Port

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
