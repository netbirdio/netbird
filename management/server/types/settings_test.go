package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtraSettings_Copy(t *testing.T) {
	src := &ExtraSettings{
		FlowEnabled:             true,
		FlowGroups:              []string{"g1"},
		UserEmailMappingEnabled: true,
	}

	dst := src.Copy()
	assert.Equal(t, src, dst, "copy should carry every field")

	dst.FlowGroups[0] = "changed"
	assert.Equal(t, "g1", src.FlowGroups[0], "copy should not share the groups slice")
}
