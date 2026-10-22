package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCountryPrefixesLimiter(t *testing.T) {
	var l countryPrefixesLimiter
	now := time.Now()

	for i := range countryPrefixesBurst {
		assert.True(t, l.allow("peer-a", now), "fetch %d of the burst should be allowed", i+1)
	}
	assert.False(t, l.allow("peer-a", now), "a fetch past the burst should be refused")
	assert.True(t, l.allow("peer-b", now), "another peer has its own budget")

	assert.True(t, l.allow("peer-a", now.Add(countryPrefixesInterval)), "the budget should refill over time")

	later := now.Add(countryPrefixesIdleTimeout + countryPrefixesInterval)
	l.allow("peer-b", later)
	_, kept := l.peers["peer-a"]
	assert.False(t, kept, "an idle peer's budget should be dropped")
}
