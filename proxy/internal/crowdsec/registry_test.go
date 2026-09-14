package crowdsec

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestRegistry_Available(t *testing.T) {
	r := NewRegistry("http://localhost:8080/", "test-key", log.NewEntry(log.StandardLogger()))
	assert.True(t, r.Available())

	r2 := NewRegistry("", "", log.NewEntry(log.StandardLogger()))
	assert.False(t, r2.Available())

	r3 := NewRegistry("http://localhost:8080/", "", log.NewEntry(log.StandardLogger()))
	assert.False(t, r3.Available())
}

func TestRegistry_Acquire_NotAvailable(t *testing.T) {
	r := NewRegistry("", "", log.NewEntry(log.StandardLogger()))
	b := r.Acquire("svc-1")
	assert.Nil(t, b)
}

func TestRegistry_Acquire_Idempotent(t *testing.T) {
	r := newTestRegistry()

	b1 := r.Acquire("svc-1")
	// Can't start without a real LAPI, but we can verify the ref tracking.
	// The bouncer will be nil because Start fails, but the ref is tracked.
	_ = b1

	assert.Len(t, r.refs, 1)

	// Second acquire of same service should not add another ref.
	r.Acquire("svc-1")
	assert.Len(t, r.refs, 1)
}

func TestRegistry_Release_Removes(t *testing.T) {
	r := newTestRegistry()
	r.refs[types.ServiceID("svc-1")] = struct{}{}

	r.Release("svc-1")
	assert.Empty(t, r.refs)
}

func TestRegistry_Release_Noop(t *testing.T) {
	r := newTestRegistry()
	// Releasing a service that was never acquired should not panic.
	r.Release("nonexistent")
	assert.Empty(t, r.refs)
}

func newTestRegistry() *Registry {
	return &Registry{
		apiURL: "http://localhost:8080/",
		apiKey: "test-key",
		logger: log.NewEntry(log.StandardLogger()),
		refs:   make(map[types.ServiceID]struct{}),
	}
}
