//go:build !unix

package dns

// probeAvailability tests all upstream servers simultaneously and
// disables/enable the resolver
func (u *upstreamResolverBase) probeAvailability() {
	u.probeViaResolution()
}
