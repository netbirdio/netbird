package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceCopyPortMappings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mappings []*PortMapping
	}{
		{name: "nil"},
		{name: "empty", mappings: []*PortMapping{}},
		{name: "nil entry", mappings: []*PortMapping{nil}},
		{name: "mapping", mappings: []*PortMapping{{
			AccountID: "account", ServiceID: "service", Protocol: ModeTCP,
			ListenPortStart: 8080, ListenPortEnd: 8080, TargetPortStart: 80, TargetPortEnd: 80,
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &Service{ID: "service", AccountID: "account", PortMappings: tc.mappings}
			copied := original.Copy()
			require.Equal(t, original.PortMappings, copied.PortMappings, "copy must preserve mapping values and nil collections")
			if len(original.PortMappings) > 0 && original.PortMappings[0] != nil {
				copied.PortMappings[0].TargetPortStart = 90
				assert.Equal(t, uint16(80), original.PortMappings[0].TargetPortStart, "mutating a copy must not change the original mapping")
			}
		})
	}
}
