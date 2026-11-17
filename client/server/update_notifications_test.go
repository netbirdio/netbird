package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

func TestCheckUpdateNotificationsDisabled(t *testing.T) {
	newServer := func(flag bool, values map[string]any) *Server {
		cfg := &profilemanager.Config{}
		cfg.ApplyMDMPolicy(mdm.NewPolicy(values))
		s := &Server{config: cfg}
		s.SetUpdateNotificationsDisabled(flag)
		return s
	}

	tests := []struct {
		name string
		srv  *Server
		want bool
	}{
		{"no config loaded yet", &Server{}, false},
		{"no policy, no flag", newServer(false, nil), false},
		{"policy silent on the key", newServer(false, map[string]any{mdm.KeyDisableProfiles: true}), false},
		{"policy true", newServer(false, map[string]any{mdm.KeyDisableUpdateNotifications: true}), true},
		{"policy string true", newServer(false, map[string]any{mdm.KeyDisableUpdateNotifications: "true"}), true},
		{"policy false", newServer(false, map[string]any{mdm.KeyDisableUpdateNotifications: false}), false},
		{"flag only", newServer(true, nil), true},
		{"flag, policy silent on the key", newServer(true, map[string]any{mdm.KeyDisableProfiles: true}), true},
		{"flag, policy true", newServer(true, map[string]any{mdm.KeyDisableUpdateNotifications: true}), true},
		{"flag, policy false overrides it", newServer(true, map[string]any{mdm.KeyDisableUpdateNotifications: false}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.srv.checkUpdateNotificationsDisabled())
		})
	}
}

func TestCheckUpdateNotificationsDisabled_FlagWithoutConfig(t *testing.T) {
	s := &Server{}
	s.SetUpdateNotificationsDisabled(true)
	assert.True(t, s.checkUpdateNotificationsDisabled(), "the install-time flag applies before any profile config is loaded")
}
