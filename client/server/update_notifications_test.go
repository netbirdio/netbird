package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

func TestCheckUpdateNotificationsDisabled(t *testing.T) {
	withPolicy := func(values map[string]any) *Server {
		cfg := &profilemanager.Config{}
		cfg.ApplyMDMPolicy(mdm.NewPolicy(values))
		return &Server{config: cfg}
	}

	tests := []struct {
		name string
		srv  *Server
		want bool
	}{
		{"no config loaded yet", &Server{}, false},
		{"no policy", withPolicy(nil), false},
		{"policy silent on the key", withPolicy(map[string]any{mdm.KeyDisableProfiles: true}), false},
		{"policy true", withPolicy(map[string]any{mdm.KeyDisableUpdateNotifications: true}), true},
		{"policy string true", withPolicy(map[string]any{mdm.KeyDisableUpdateNotifications: "true"}), true},
		{"policy false", withPolicy(map[string]any{mdm.KeyDisableUpdateNotifications: false}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.srv.checkUpdateNotificationsDisabled())
		})
	}
}
