package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestPersistLoginOverrides(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name           string
		initialMgmtURL string
		initialPSK     string
		newMgmtURL     string
		newPSK         *string
		wantMgmtURL    string
		wantPSK        string
	}{
		{
			name:           "persist new management URL",
			initialMgmtURL: "https://old.example.com:33073",
			newMgmtURL:     "https://new.example.com:33073",
			wantMgmtURL:    "https://new.example.com:33073",
		},
		{
			name:           "persist new pre-shared key",
			initialMgmtURL: "https://existing.example.com:33073",
			initialPSK:     "old-key",
			newPSK:         strPtr("new-key"),
			wantMgmtURL:    "https://existing.example.com:33073",
			wantPSK:        "new-key",
		},
		{
			name:           "persist both",
			initialMgmtURL: "https://old.example.com:33073",
			initialPSK:     "old-key",
			newMgmtURL:     "https://new.example.com:33073",
			newPSK:         strPtr("new-key"),
			wantMgmtURL:    "https://new.example.com:33073",
			wantPSK:        "new-key",
		},
		{
			name:           "no inputs preserves existing",
			initialMgmtURL: "https://existing.example.com:33073",
			initialPSK:     "existing-key",
			wantMgmtURL:    "https://existing.example.com:33073",
			wantPSK:        "existing-key",
		},
		{
			name:           "empty PSK pointer is ignored",
			initialMgmtURL: "https://existing.example.com:33073",
			initialPSK:     "existing-key",
			newPSK:         strPtr(""),
			wantMgmtURL:    "https://existing.example.com:33073",
			wantPSK:        "existing-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origDefault := profilemanager.DefaultConfigPath
			t.Cleanup(func() { profilemanager.DefaultConfigPath = origDefault })

			dir := t.TempDir()
			profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")

			seed := profilemanager.ConfigInput{
				ConfigPath:    profilemanager.DefaultConfigPath,
				ManagementURL: tt.initialMgmtURL,
			}
			if tt.initialPSK != "" {
				seed.PreSharedKey = strPtr(tt.initialPSK)
			}
			_, err := profilemanager.UpdateOrCreateConfig(seed)
			require.NoError(t, err, "seed config")

			activeProf := &profilemanager.ActiveProfileState{Name: "default"}
			err = persistLoginOverrides(activeProf, tt.newMgmtURL, tt.newPSK)
			require.NoError(t, err, "persistLoginOverrides")

			cfg, err := profilemanager.ReadConfig(profilemanager.DefaultConfigPath)
			require.NoError(t, err, "read back config")

			require.Equal(t, tt.wantMgmtURL, cfg.ManagementURL.String(), "management URL")
			require.Equal(t, tt.wantPSK, cfg.PreSharedKey, "pre-shared key")
		})
	}
}
