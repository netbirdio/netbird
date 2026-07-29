//go:build !ios && !android

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMigrateLegacyDaemonAddrForOS(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		addr    string
		want    string
		migrate bool
	}{
		{
			name:    "windows legacy tcp migrates to pipe",
			goos:    "windows",
			addr:    legacyWindowsDaemonAddr,
			want:    windowsPipeDaemonAddr,
			migrate: true,
		},
		{
			name:    "windows pipe already migrated stays",
			goos:    "windows",
			addr:    windowsPipeDaemonAddr,
			want:    windowsPipeDaemonAddr,
			migrate: false,
		},
		{
			name:    "windows custom tcp left alone",
			goos:    "windows",
			addr:    "tcp://127.0.0.1:9999",
			want:    "tcp://127.0.0.1:9999",
			migrate: false,
		},
		{
			name:    "linux legacy-looking tcp not migrated",
			goos:    "linux",
			addr:    legacyWindowsDaemonAddr,
			want:    legacyWindowsDaemonAddr,
			migrate: false,
		},
		{
			name:    "linux unix socket untouched",
			goos:    "linux",
			addr:    "unix:///var/run/netbird.sock",
			want:    "unix:///var/run/netbird.sock",
			migrate: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := migrateLegacyDaemonAddrForOS(tc.goos, tc.addr)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.migrate, ok)
		})
	}
}
