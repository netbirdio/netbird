package cmd

import (
	"fmt"
	"os/user"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestLogin(t *testing.T) {
	mgmAddr := startTestingServices(t)

	tempDir := t.TempDir()

	currUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
		return
	}

	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	sm := profilemanager.ServiceManager{}
	err = sm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		Name:     "default",
		Username: currUser.Username,
	})
	if err != nil {
		t.Fatalf("failed to set active profile state: %v", err)
	}

	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
	})

	mgmtURL := fmt.Sprintf("http://%s", mgmAddr)
	rootCmd.SetArgs([]string{
		"login",
		"--log-file",
		util.LogConsole,
		"--setup-key",
		strings.ToUpper("a2c8e62b-38f5-4553-b31e-dd66c696cebb"),
		"--management-url",
		mgmtURL,
	})
	// TODO(hakan): fix this test
	_ = rootCmd.Execute()
}
