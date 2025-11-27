//go:build !ios

package dns

import (
	"context"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

func TestDarwinDNSUncleanShutdownCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scutil integration test in short mode")
	}

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "state.json")

	sm := statemanager.New(stateFile)
	sm.RegisterState(&ShutdownState{})
	sm.Start()
	defer func() {
		require.NoError(t, sm.Stop(context.Background()))
	}()

	configurator := &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}

	config := HostDNSConfig{
		ServerIP:   netip.MustParseAddr("100.64.0.1"),
		ServerPort: 53,
		RouteAll:   true,
		Domains: []DomainConfig{
			{Domain: "example.com", MatchOnly: true},
		},
	}

	err := configurator.applyDNSConfig(config, sm)
	require.NoError(t, err)

	require.NoError(t, sm.PersistState(context.Background()))

	searchKey := getKeyWithInput(netbirdDNSStateKeyFormat, searchSuffix)
	matchKey := getKeyWithInput(netbirdDNSStateKeyFormat, matchSuffix)
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix)

	defer func() {
		for _, key := range []string{searchKey, matchKey, localKey} {
			_ = removeTestDNSKey(key)
		}
	}()

	for _, key := range []string{searchKey, matchKey, localKey} {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		if exists {
			t.Logf("Key %s exists before cleanup", key)
		}
	}

	sm2 := statemanager.New(stateFile)
	sm2.RegisterState(&ShutdownState{})
	err = sm2.LoadState(&ShutdownState{})
	require.NoError(t, err)

	state := sm2.GetState(&ShutdownState{})
	if state == nil {
		t.Skip("State not saved, skipping cleanup test")
	}

	shutdownState, ok := state.(*ShutdownState)
	require.True(t, ok)

	err = shutdownState.Cleanup()
	require.NoError(t, err)

	for _, key := range []string{searchKey, matchKey, localKey} {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "Key %s should NOT exist after cleanup", key)
	}
}

func checkDNSKeyExists(key string) (bool, error) {
	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader("show " + key + "\nquit\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such key") {
			return false, nil
		}
		return false, err
	}
	return !strings.Contains(string(output), "No such key"), nil
}

func removeTestDNSKey(key string) error {
	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader("remove " + key + "\nquit\n")
	_, err := cmd.CombinedOutput()
	return err
}
