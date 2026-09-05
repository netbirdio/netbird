//go:build !android && !ios && !freebsd && !js

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

func TestApplyMDMRestrictions_VNCFields(t *testing.T) {
	t.Run("unmanaged leaves fields at zero", func(t *testing.T) {
		var mdm MDMFields
		applyMDMRestrictions(&mdm, &proto.GetConfigResponse{})
		assert.Nil(t, mdm.AllowServerVNC)
		assert.False(t, mdm.DisableVNCApproval)
	})

	t.Run("managed surfaces enforced values", func(t *testing.T) {
		var mdm MDMFields
		applyMDMRestrictions(&mdm, &proto.GetConfigResponse{
			MDMManagedFields:   []string{"allowServerVNC", "disableVNCApproval"},
			ServerVNCAllowed:   true,
			DisableVNCApproval: true,
		})
		require.NotNil(t, mdm.AllowServerVNC)
		assert.True(t, *mdm.AllowServerVNC, "AllowServerVNC should carry the enforced value")
		assert.True(t, mdm.DisableVNCApproval, "DisableVNCApproval should be flagged managed")
	})

	t.Run("managed VNC disallowed surfaces false", func(t *testing.T) {
		var mdm MDMFields
		applyMDMRestrictions(&mdm, &proto.GetConfigResponse{
			MDMManagedFields: []string{"allowServerVNC"},
			ServerVNCAllowed: false,
		})
		require.NotNil(t, mdm.AllowServerVNC)
		assert.False(t, *mdm.AllowServerVNC)
		assert.False(t, mdm.DisableVNCApproval, "unmanaged approval stays zero")
	})
}
