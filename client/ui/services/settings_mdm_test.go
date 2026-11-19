//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/mdm"
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

// The settings form sends every field back on save, the hidden MDM-managed ones
// included. Those carry the enforced value, not a choice of the user, so they
// must not reach the daemon.
func TestSetConfigLeavesOutMDMManagedFields(t *testing.T) {
	daemon := &stubDaemon{
		stored:    &proto.GetConfigResponse{MDMManagedFields: []string{mdm.KeyMTU, mdm.KeyAllowServerSSH}},
		setConfig: func(*proto.SetConfigRequest) error { return nil },
	}
	s := &Settings{conn: stubConn{client: daemon}, daemonAddr: testDaemonAddr}

	mtu, port, on := int64(1300), int64(51821), true
	_, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:      "default",
		MTU:              &mtu,
		ServerSSHAllowed: &on,
		WireguardPort:    &port,
	})
	require.NoError(t, err)

	require.Len(t, daemon.requests, 1, "one request")
	sent := daemon.requests[0]
	assert.Nil(t, sent.Mtu, "a managed field must be left out")
	assert.Nil(t, sent.ServerSSHAllowed, "a managed field must be left out")
	assert.Equal(t, port, sent.GetWireguardPort(), "an unmanaged field is still sent")
}

// mdmKeysWithoutRequestField are restriction keys the settings form never
// sends: they gate the UI or the daemon, not a field of the save request.
var mdmKeysWithoutRequestField = map[string]bool{
	mdm.KeyDisableAutostart:         true,
	mdm.KeyDisableMetricsCollection: true,
	mdm.KeySplitTunnelMode:          true,
	mdm.KeySplitTunnelApps:          true,
	mdm.KeyDisableAdvancedView:      true,
	mdm.KeyKeepConnectedOnQuit:      true,
}

// A key the UI reports as managed but the save keeps sending would be persisted
// as the user's choice. Every restriction key must have a field to clear.
func TestMDMRequestFieldsCoverRestrictionKeys(t *testing.T) {
	fields := reflect.TypeOf(mdm.Fields{})
	for i := 0; i < fields.NumField(); i++ {
		key := fields.Field(i).Tag.Get("json")
		if mdmKeysWithoutRequestField[key] {
			continue
		}
		_, ok := mdmRequestFields[key]
		assert.Truef(t, ok, "restriction key %q has no request field to leave out", key)
	}
}

func TestMDMRequestFieldsClearTheirField(t *testing.T) {
	for key, drop := range mdmRequestFields {
		req := fullSetConfigRequest()
		drop(req)
		assert.Falsef(t, gproto.Equal(req, fullSetConfigRequest()), "clearing %q must change the request", key)
	}
}

func fullSetConfigRequest() *proto.SetConfigRequest {
	b, s, i, ttl := true, "x", int64(1), int32(60)
	return &proto.SetConfigRequest{
		ManagementUrl:                 "https://mgmt.example.com",
		OptionalPreSharedKey:          &s,
		WireguardPort:                 &i,
		RosenpassEnabled:              &b,
		RosenpassPermissive:           &b,
		DisableClientRoutes:           &b,
		DisableServerRoutes:           &b,
		ServerSSHAllowed:              &b,
		DisableAutoConnect:            &b,
		BlockInbound:                  &b,
		RemoteJobsAllowed:             &b,
		ServerVNCAllowed:              &b,
		DisableVNCApproval:            &b,
		InterfaceName:                 &s,
		Mtu:                           &i,
		DisableDns:                    &b,
		DisableIpv6:                   &b,
		DisableFirewall:               &b,
		BlockLanAccess:                &b,
		DisableNotifications:          &b,
		NetworkMonitor:                &b,
		EnableSSHRoot:                 &b,
		EnableSSHSFTP:                 &b,
		EnableSSHLocalPortForwarding:  &b,
		EnableSSHRemotePortForwarding: &b,
		DisableSSHAuth:                &b,
		SshJWTCacheTTL:                &ttl,
	}
}
