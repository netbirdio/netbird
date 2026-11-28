package profilemanager

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetActiveProfileStateNoWarnWhenConfigDirUnavailable(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("baseConfigDir uses user.Current() on darwin")
	}

	blockingPath := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blockingPath, nil, 0o600))

	t.Setenv("XDG_CONFIG_HOME", blockingPath)
	t.Setenv("AppData", blockingPath)

	origEuid := geteuid
	origOverride := ConfigDirOverride
	geteuid = func() int { return 1000 }
	ConfigDirOverride = ""
	t.Cleanup(func() {
		geteuid = origEuid
		ConfigDirOverride = origOverride
	})

	logger := log.StandardLogger()
	origHooks := logger.ReplaceHooks(make(log.LevelHooks))
	origLevel := logger.GetLevel()
	origOut := logger.Out
	logger.SetLevel(log.DebugLevel)
	logger.SetOutput(io.Discard)
	hook := test.NewGlobal()
	t.Cleanup(func() {
		hook.Reset()
		logger.ReplaceHooks(origHooks)
		logger.SetLevel(origLevel)
		logger.SetOutput(origOut)
	})

	assert.Equal(t, ID(defaultProfileName), NewProfileManager().getActiveProfileState())

	var configDirEntry *log.Entry
	for _, entry := range hook.AllEntries() {
		assert.Greater(t, entry.Level, log.WarnLevel,
			"unexpected warning/error log when config directory is unavailable: %s", entry.Message)
		if strings.Contains(entry.Message, "failed to get config directory") {
			configDirEntry = entry
		}
	}
	require.NotNil(t, configDirEntry, "expected debug log for unavailable config directory")
	assert.Equal(t, log.DebugLevel, configDirEntry.Level)
}
