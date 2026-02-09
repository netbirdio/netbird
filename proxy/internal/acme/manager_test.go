package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostPolicy(t *testing.T) {
	mgr := NewManager(t.TempDir(), "https://acme.example.com/directory", nil, nil, "")
	mgr.AddDomain("example.com", "acc1", "rp1")

	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name: "exact domain match",
			host: "example.com",
		},
		{
			name: "domain with port",
			host: "example.com:443",
		},
		{
			name:    "unknown domain",
			host:    "unknown.com",
			wantErr: true,
		},
		{
			name:    "unknown domain with port",
			host:    "unknown.com:443",
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    "",
			wantErr: true,
		},
		{
			name:    "port only",
			host:    ":443",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.hostPolicy(context.Background(), tc.host)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unknown domain")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
