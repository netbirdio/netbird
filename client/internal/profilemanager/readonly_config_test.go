package profilemanager

import (
	"bytes"
	"errors"
	"os/user"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetActiveProfileStateNoWarnWhenConfigDirUnavailable(t *testing.T) {
	fakeSudo(t, filepath.Join("/home", "misha"))
	lookupUser = func(string) (*user.User, error) {
		return nil, errors.New("nss unavailable")
	}

	var logs bytes.Buffer
	logger := log.StandardLogger()
	previousOutput := logger.Out
	logger.SetOutput(&logs)
	t.Cleanup(func() { logger.SetOutput(previousOutput) })

	assert.Equal(t, ID(defaultProfileName), NewProfileManager().getActiveProfileState())
	assert.NotContains(t, logs.String(), "failed to get config directory",
		"an unavailable config directory must fall back silently to the default profile")
}
