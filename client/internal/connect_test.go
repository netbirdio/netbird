package internal

import (
	"net"
	"testing"
)

func Test_freePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		want    int
		wantErr bool
	}{
		{
			name:    "available",
			port:    51820,
			want:    51820,
			wantErr: false,
		},
		{
			name:    "notavailable",
			port:    51830,
			want:    51831,
			wantErr: false,
		},
		{
			name:    "noports",
			port:    65535,
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {

		c1, err := net.ListenUDP("udp", &net.UDPAddr{Port: 51830})
		if err != nil {
			t.Errorf("freePort error = %v", err)
		}
		c2, err := net.ListenUDP("udp", &net.UDPAddr{Port: 65535})
		if err != nil {
			t.Errorf("freePort error = %v", err)
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := freePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("freePort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("freePort() = %v, want %v", got, tt.want)
			}
		})
		c1.Close()
		c2.Close()
	}
}
