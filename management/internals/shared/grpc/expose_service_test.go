package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestExposeAccessRestrictionsFromProtoCopiesCrowdSecMode(t *testing.T) {
	got := exposeAccessRestrictionsFromProto(&proto.AccessRestrictions{
		AllowedCidrs:     []string{"203.0.113.0/24"},
		BlockedCidrs:     []string{"198.51.100.0/24"},
		AllowedCountries: []string{"US"},
		BlockedCountries: []string{"DE"},
		CrowdsecMode:     "observe",
	})

	assert.Equal(t, []string{"203.0.113.0/24"}, got.AllowedCIDRs)
	assert.Equal(t, []string{"198.51.100.0/24"}, got.BlockedCIDRs)
	assert.Equal(t, []string{"US"}, got.AllowedCountries)
	assert.Equal(t, []string{"DE"}, got.BlockedCountries)
	assert.Equal(t, "observe", got.CrowdSecMode)
}
