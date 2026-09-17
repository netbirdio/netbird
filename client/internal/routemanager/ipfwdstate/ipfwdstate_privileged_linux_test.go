//go:build privileged

package ipfwdstate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestRoutingV6ToV4Transition verifies that a v4-only routing request
// releases a previously held routing-owned v6 reference without touching
// references held by DNAT rules.
func TestRequestRoutingV6ToV4Transition(t *testing.T) {
	f := NewIPForwardingState("wt-fwd-test")

	require.NoError(t, f.RequestRouting(true), "request routing with v6")
	v4, v6 := f.Counts()
	assert.Equal(t, 1, v4, "v4 reference held")
	assert.Equal(t, 1, v6, "v6 reference held")

	require.NoError(t, f.RequestRouting(false), "request routing v4-only")
	v4, v6 = f.Counts()
	assert.Equal(t, 1, v4, "v4 reference kept")
	assert.Equal(t, 0, v6, "routing-owned v6 reference released")

	// A DNAT-held reference survives a v4-only routing request.
	require.NoError(t, f.RequestForwarding(true), "dnat v6 reference")
	require.NoError(t, f.RequestRouting(false), "repeat v4-only request")
	_, v6 = f.Counts()
	assert.Equal(t, 1, v6, "dnat-held v6 reference survives")
	require.NoError(t, f.ReleaseForwarding(true), "release dnat v6 reference")

	require.NoError(t, f.ReleaseRouting(), "release routing")
	v4, v6 = f.Counts()
	assert.Equal(t, 0, v4, "all v4 references released")
	assert.Equal(t, 0, v6, "all v6 references released")
}
