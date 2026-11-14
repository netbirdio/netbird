package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtraSettings_Copy(t *testing.T) {
	src := &ExtraSettings{
		PeerApprovalEnabled:       true,
		UserApprovalRequired:      true,
		IntegratedValidator:       "validator",
		IntegratedValidatorGroups: []string{"v1"},
		FlowEnabled:               true,
		FlowGroups:                []string{"g1"},
		FlowPacketCounterEnabled:  true,
		FlowENCollectionEnabled:   true,
		FlowDnsCollectionEnabled:  true,
		UserEmailMappingEnabled:   true,
	}

	dst := src.Copy()
	assert.Equal(t, src, dst, "copy should carry every field")

	dst.FlowGroups[0] = "changed"
	assert.Equal(t, "g1", src.FlowGroups[0], "copy should not share the groups slice")

	dst.IntegratedValidatorGroups[0] = "changed"
	assert.Equal(t, "v1", src.IntegratedValidatorGroups[0], "copy should not share the validator groups slice")
}
