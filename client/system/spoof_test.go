package system

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestSpoof_PostureChecksAndFlags(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(SpoofDirEnv, tempDir)

	trueVal := true
	falseVal := false
	spoofedHost := "spoofed-test-host"

	cfg := SpoofConfig{
		Hostname:         &spoofedHost,
		ServerSSHAllowed: &trueVal,
		DisableIPv6:      &trueVal,
		Flags: &SpoofFlags{
			RemoteJobsAllowed:   &trueVal,
			DisableClientRoutes: &trueVal,
		},
		PostureChecks: &SpoofPostureChecks{
			All: &trueVal,
			Files: map[string]bool{
				"/opt/blocked/file": false,
				"custom-bad":        false,
			},
			Processes: map[string]bool{
				"/usr/bin/stopped-proc": false,
			},
		},
	}

	cfgData, err := json.Marshal(cfg)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tempDir, "overrides.json"), cfgData, 0600)
	require.NoError(t, err)

	checks := []*mgmProto.Checks{
		{
			Files: []string{
				"/opt/test/some-file",
				"/opt/blocked/file",
				"/var/run/custom-bad",
				"/usr/bin/stopped-proc",
			},
		},
	}

	info, err := GetInfoWithChecks(context.Background(), checks)
	require.NoError(t, err)
	assert.Equal(t, "spoofed-test-host", info.Hostname)

	// Check flags
	assert.True(t, info.ServerSSHAllowed)
	assert.True(t, info.RemoteJobsAllowed)
	assert.True(t, info.DisableClientRoutes)
	assert.True(t, info.DisableIPv6)

	// Even if SetFlags tries to set them to false, spoofing overrides should prevail
	info.SetFlags(false, false, &falseVal, false, false, false, false, false, false, false, nil, nil, nil, nil, nil, nil, &falseVal)
	assert.True(t, info.ServerSSHAllowed)
	assert.True(t, info.RemoteJobsAllowed)
	assert.True(t, info.DisableClientRoutes)
	assert.True(t, info.DisableIPv6)

	// Check posture check results
	require.Len(t, info.Files, 4)

	// /opt/test/some-file: All=true applies
	assert.Equal(t, "/opt/test/some-file", info.Files[0].Path)
	assert.True(t, info.Files[0].Exist)
	assert.True(t, info.Files[0].ProcessIsRunning)

	// /opt/blocked/file: Files override false applies to Exist, ProcessIsRunning defaults to All (true)
	assert.Equal(t, "/opt/blocked/file", info.Files[1].Path)
	assert.False(t, info.Files[1].Exist)
	assert.True(t, info.Files[1].ProcessIsRunning)

	// /var/run/custom-bad: Basename match applies to Exist (false)
	assert.Equal(t, "/var/run/custom-bad", info.Files[2].Path)
	assert.False(t, info.Files[2].Exist)
	assert.True(t, info.Files[2].ProcessIsRunning)

	// /usr/bin/stopped-proc: Processes override false applies to ProcessIsRunning
	assert.Equal(t, "/usr/bin/stopped-proc", info.Files[3].Path)
	assert.True(t, info.Files[3].Exist)
	assert.False(t, info.Files[3].ProcessIsRunning)

	// Verify posture_checks.json exists and is valid JSON
	jsonPath := filepath.Join(tempDir, "posture_checks.json")
	assert.FileExists(t, jsonPath)
	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	var record PostureCheckRecord
	err = json.Unmarshal(jsonData, &record)
	require.NoError(t, err)
	assert.Len(t, record.RequestedPaths, 4)
	assert.Len(t, record.Reported, 4)

	// Verify posture_checks.log exists
	logPath := filepath.Join(tempDir, "posture_checks.log")
	assert.FileExists(t, logPath)
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(logData), "received 4 posture check(s)")
}
