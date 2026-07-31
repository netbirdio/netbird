package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

func TestValidateProviderAPIKey(t *testing.T) {
	key := "secret"
	empty := ""

	tests := []struct {
		name     string
		mode     catalog.AuthMode
		apiKey   *string
		creating bool
		wantErr  string
	}{
		{name: "required create with key", mode: catalog.AuthModeRequired, apiKey: &key, creating: true},
		{name: "required create omitted", mode: catalog.AuthModeRequired, creating: true, wantErr: "required"},
		{name: "required update omitted preserves", mode: catalog.AuthModeRequired},
		{name: "required update explicit empty", mode: catalog.AuthModeRequired, apiKey: &empty, wantErr: "required"},
		{name: "optional create omitted", mode: catalog.AuthModeOptional, creating: true},
		{name: "optional update explicit empty", mode: catalog.AuthModeOptional, apiKey: &empty},
		{name: "optional with key", mode: catalog.AuthModeOptional, apiKey: &key, creating: true},
		{name: "none omitted", mode: catalog.AuthModeNone, creating: true},
		{name: "none explicit empty", mode: catalog.AuthModeNone, apiKey: &empty},
		{name: "none with key", mode: catalog.AuthModeNone, apiKey: &key, wantErr: "not supported"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := catalog.Provider{ID: "test-provider", AuthMode: tt.mode}
			err := validateProviderAPIKey(entry, tt.apiKey, tt.creating)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
