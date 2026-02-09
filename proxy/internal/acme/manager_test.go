package acme

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostPolicy(t *testing.T) {
	mgr := NewManager(t.TempDir(), "https://acme.example.com/directory", nil, nil, "")
	mgr.AddDomain("example.com", "acc1", "rp1")

	// Wait for the background prefetch goroutine to finish so the temp dir
	// can be cleaned up without a race.
	t.Cleanup(func() {
		assert.Eventually(t, func() bool {
			return mgr.PendingCerts() == 0
		}, 30*time.Second, 50*time.Millisecond)
	})

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

func TestDomainStates(t *testing.T) {
	mgr := NewManager(t.TempDir(), "https://acme.example.com/directory", nil, nil, "")

	assert.Equal(t, 0, mgr.PendingCerts(), "initially zero")
	assert.Equal(t, 0, mgr.TotalDomains(), "initially zero domains")
	assert.Empty(t, mgr.PendingDomains())
	assert.Empty(t, mgr.ReadyDomains())
	assert.Empty(t, mgr.FailedDomains())

	// AddDomain starts as pending, then the prefetch goroutine will fail
	// (no real ACME server) and transition to failed.
	mgr.AddDomain("a.example.com", "acc1", "rp1")
	mgr.AddDomain("b.example.com", "acc1", "rp1")

	assert.Equal(t, 2, mgr.TotalDomains(), "two domains registered")

	// Pending domains should eventually drain after prefetch goroutines finish.
	assert.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 30*time.Second, 100*time.Millisecond, "pending certs should return to zero after prefetch completes")

	assert.Empty(t, mgr.PendingDomains())
	assert.Equal(t, 2, mgr.TotalDomains(), "total domains unchanged")

	// With a fake ACME URL, both should have failed.
	failed := mgr.FailedDomains()
	assert.Len(t, failed, 2, "both domains should have failed")
	assert.Contains(t, failed, "a.example.com")
	assert.Contains(t, failed, "b.example.com")
	assert.Empty(t, mgr.ReadyDomains())
}
