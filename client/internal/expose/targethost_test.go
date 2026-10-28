package expose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTargetHost(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "hostname", in: "other-service", want: "other-service"},
		{name: "ipv4", in: "10.0.0.29", want: "10.0.0.29"},
		{name: "ipv6", in: "2001:db8::1", want: "2001:db8::1"},
		{name: "ipv6 brackets", in: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "trim space", in: "  db.internal  ", want: "db.internal"},
		{name: "empty", in: "", wantErr: "empty"},
		{name: "whitespace", in: "  ", wantErr: "empty"},
		{name: "scheme", in: "http://other-service", wantErr: "scheme"},
		{name: "port", in: "other-service:8080", wantErr: "port"},
		{name: "path", in: "other-service/app", wantErr: "path"},
		{name: "loopback ipv4", in: "127.0.0.1", wantErr: "loopback"},
		{name: "loopback ipv6", in: "::1", wantErr: "loopback"},
		{name: "localhost", in: "localhost", wantErr: "loopback"},
		{name: "mapped loopback", in: "::ffff:127.0.0.1", wantErr: "loopback"},
		{name: "unspecified", in: "0.0.0.0", wantErr: "invalid target host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeTargetHost(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
