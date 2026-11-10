package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestCountryPrefixesLimiter(t *testing.T) {
	var l countryPrefixesLimiter
	now := time.Now()
	peerA, peerB := wgtypes.Key{1}, wgtypes.Key{2}
	usA := countryPrefixesKey{peer: peerA, country: "US"}
	usB := countryPrefixesKey{peer: peerB, country: "US"}

	for i := range countryPrefixesBurst {
		assert.True(t, l.allow(usA, now), "fetch %d of the burst should be allowed", i+1)
	}
	assert.False(t, l.allow(usA, now), "a fetch past the burst should be refused")
	assert.True(t, l.allow(countryPrefixesKey{peer: peerA, country: "CA"}, now), "each country has its own budget")
	assert.True(t, l.allow(usB, now), "another peer has its own budget")

	assert.True(t, l.allow(usA, now.Add(countryPrefixesInterval)), "the budget should refill over time")

	later := now.Add(countryPrefixesIdleTimeout + countryPrefixesInterval)
	l.allow(usB, later)
	_, kept := l.budgets[usA]
	assert.False(t, kept, "an idle budget should be dropped")
}

// TestCountryPrefixesLimiter_AllCountriesAtOnce covers a peer installing routes for many
// countries at once: every code is fetched by the route handler and by the route ACL, and
// none of those fetches may be refused.
func TestCountryPrefixesLimiter_AllCountriesAtOnce(t *testing.T) {
	var l countryPrefixesLimiter
	now := time.Now()
	peer := wgtypes.Key{1}

	for first := 'A'; first <= 'Z'; first++ {
		for second := 'A'; second <= 'Z'; second++ {
			key := countryPrefixesKey{peer: peer, country: string([]rune{first, second})}
			assert.True(t, l.allow(key, now), "the route handler fetch of %s should be allowed", key.country)
			assert.True(t, l.allow(key, now), "the route ACL fetch of %s should be allowed", key.country)
		}
	}
}
