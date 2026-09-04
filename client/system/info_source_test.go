package system

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestInfoSource_CurrentBeforeRefresh(t *testing.T) {
	var src InfoSource

	info := src.Current(context.Background())

	assert.Empty(t, info.Files)
}

func TestInfoSource_CurrentReusesRefreshedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	checks := []*proto.Checks{{Files: []string{path}}}

	var src InfoSource
	refreshed, ok := src.Refresh(context.Background(), 15*time.Second, checks)
	require.True(t, ok)
	require.Equal(t, []File{{Path: path, Exist: true}}, refreshed.Files)

	info := src.Current(context.Background())

	assert.Equal(t, refreshed.Files, info.Files)
}

func TestInfoSource_CurrentExcludesAddresses(t *testing.T) {
	addrs := GetInfo(context.Background()).NetworkAddresses
	if len(addrs) == 0 {
		t.Skip("no network addresses on this host")
	}
	excluded := addrs[0].NetIP.Addr()
	matching := 0
	for _, addr := range addrs {
		if addr.NetIP.Addr() == excluded {
			matching++
		}
	}

	var src InfoSource
	info := src.Current(context.Background(), excluded)

	assert.Len(t, info.NetworkAddresses, len(addrs)-matching)
	for _, addr := range info.NetworkAddresses {
		assert.NotEqual(t, excluded, addr.NetIP.Addr())
	}
}
