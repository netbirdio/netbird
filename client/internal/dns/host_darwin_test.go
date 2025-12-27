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

func TestParseSystemConfigOutput_Complete(t *testing.T) {
	mockOutput := `<dictionary> {
  DomainName : example.com
  SearchDomains : <array> {
    0 : internal.local
    1 : corp.example.com
  }
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : 8.8.8.8
  }
}`

	result, err := parseSystemConfigOutput([]byte(mockOutput))
	require.NoError(t, err)

	assert.Equal(t, 53, result.ServerPort)
	assert.Len(t, result.Domains, 3)
	assert.Contains(t, result.Domains, "example.com")
	assert.Contains(t, result.Domains, "internal.local")
	assert.Contains(t, result.Domains, "corp.example.com")

	assert.Len(t, result.ServerIPs, 2)
	assert.Equal(t, "192.168.1.1", result.ServerIPs[0].String())
	assert.Equal(t, "8.8.8.8", result.ServerIPs[1].String())
}

func TestParseSystemConfigOutput_MultipleServers(t *testing.T) {
	mockOutput := `<dictionary> {
  DomainName : test.local
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : 10.0.0.1
    2 : 2001:4860:4860::8888
    3 : fd00::1
  }
}`

	result, err := parseSystemConfigOutput([]byte(mockOutput))
	require.NoError(t, err)

	assert.Len(t, result.ServerIPs, 4)
	assert.Equal(t, "192.168.1.1", result.ServerIPs[0].String())
	assert.Equal(t, "10.0.0.1", result.ServerIPs[1].String())
	assert.Equal(t, "2001:4860:4860::8888", result.ServerIPs[2].String())
	assert.Equal(t, "fd00::1", result.ServerIPs[3].String())
}

func TestParseSystemConfigOutput_DomainDeduplication(t *testing.T) {
	mockOutput := `<dictionary> {
  DomainName : example.com
  SearchDomains : <array> {
    0 : example.com
    1 : internal.local
    2 : example.com
  }
  ServerAddresses : <array> {
    0 : 192.168.1.1
  }
}`

	result, err := parseSystemConfigOutput([]byte(mockOutput))
	require.NoError(t, err)

	assert.Len(t, result.Domains, 2)
	assert.Contains(t, result.Domains, "example.com")
	assert.Contains(t, result.Domains, "internal.local")

	domainCount := make(map[string]int)
	for _, domain := range result.Domains {
		domainCount[domain]++
	}
	assert.Equal(t, 1, domainCount["example.com"])
}

func TestParseSystemConfigOutput_EmptyOutput(t *testing.T) {
	result, err := parseSystemConfigOutput([]byte(""))
	require.NoError(t, err)

	assert.Equal(t, 53, result.ServerPort)
	assert.Empty(t, result.Domains)
	assert.Empty(t, result.ServerIPs)
}

func TestParseSystemConfigOutput_InvalidIP(t *testing.T) {
	mockOutput := `<dictionary> {
  DomainName : test.local
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : invalid-ip
    2 : 8.8.8.8
    3 : 999.999.999.999
  }
}`

	result, err := parseSystemConfigOutput([]byte(mockOutput))
	require.NoError(t, err)

	assert.Len(t, result.ServerIPs, 2)
	assert.Equal(t, "192.168.1.1", result.ServerIPs[0].String())
	assert.Equal(t, "8.8.8.8", result.ServerIPs[1].String())
}

func TestParseSystemConfigOutput_OnlyDomainName(t *testing.T) {
	mockOutput := `<dictionary> {
  DomainName : example.com
}`

	result, err := parseSystemConfigOutput([]byte(mockOutput))
	require.NoError(t, err)

	assert.Len(t, result.Domains, 1)
	assert.Equal(t, "example.com", result.Domains[0])
	assert.Empty(t, result.ServerIPs)
	assert.Equal(t, 53, result.ServerPort)
}

func TestParseSystemConfigOutput_NestedArrays(t *testing.T) {
	mockOutput := `<dictionary> {
  DomainName : example.com
  SearchDomains : <array> {
    0 : search1.local
    1 : search2.local
  }
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : 192.168.1.2
  }
  OtherField : value
}`

	result, err := parseSystemConfigOutput([]byte(mockOutput))
	require.NoError(t, err)

	assert.Len(t, result.Domains, 3)
	assert.Contains(t, result.Domains, "example.com")
	assert.Contains(t, result.Domains, "search1.local")
	assert.Contains(t, result.Domains, "search2.local")

	assert.Len(t, result.ServerIPs, 2)
	assert.Equal(t, "192.168.1.1", result.ServerIPs[0].String())
	assert.Equal(t, "192.168.1.2", result.ServerIPs[1].String())
}
