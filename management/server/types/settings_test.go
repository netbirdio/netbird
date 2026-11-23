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

func TestExtraSettings_CopyIntegrationFieldsFrom(t *testing.T) {
	src := &ExtraSettings{
		FlowEnabled:              true,
		FlowGroups:               []string{"g1", "g2"},
		FlowPacketCounterEnabled: true,
		FlowENCollectionEnabled:  true,
		FlowDnsCollectionEnabled: true,
		UserEmailMappingEnabled:  true,
	}
	dst := &ExtraSettings{
		PeerApprovalEnabled:       true,
		UserApprovalRequired:      true,
		IntegratedValidator:       "validator",
		IntegratedValidatorGroups: []string{"v1", "v2"},
	}

	dst.CopyIntegrationFieldsFrom(src)

	assert.Equal(t, src.FlowEnabled, dst.FlowEnabled, "flow enabled should be copied")
	assert.Equal(t, []string{"g1", "g2"}, dst.FlowGroups, "flow groups should be copied")
	assert.Equal(t, src.FlowPacketCounterEnabled, dst.FlowPacketCounterEnabled, "packet counter flag should be copied")
	assert.Equal(t, src.FlowENCollectionEnabled, dst.FlowENCollectionEnabled, "EN collection flag should be copied")
	assert.Equal(t, src.FlowDnsCollectionEnabled, dst.FlowDnsCollectionEnabled, "DNS collection flag should be copied")
	assert.Equal(t, src.UserEmailMappingEnabled, dst.UserEmailMappingEnabled, "user email mapping flag should be copied")

	assert.True(t, dst.PeerApprovalEnabled, "peer approval should be left untouched")
	assert.True(t, dst.UserApprovalRequired, "user approval should be left untouched")
	assert.Equal(t, "validator", dst.IntegratedValidator, "integrated validator should be left untouched")
	assert.Equal(t, []string{"v1", "v2"}, dst.IntegratedValidatorGroups, "validator groups should be left untouched")

	src.FlowGroups[0] = "changed"
	assert.Equal(t, "g1", dst.FlowGroups[0], "destination should not share the source groups slice")
}
