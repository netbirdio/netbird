package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestLogin(t *testing.T) {
	mgmAddr := startTestingServices(t)

	tempDir := t.TempDir()

	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	sm := profilemanager.ServiceManager{}
	err := sm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		Name: "default",
		Path: profilemanager.DefaultConfigPathDir + "/default.json",
	})

	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
	})

	mgmtURL := fmt.Sprintf("http://%s", mgmAddr)
	rootCmd.SetArgs([]string{
		"login",
		"--log-file",
		"console",
		"--setup-key",
		strings.ToUpper("a2c8e62b-38f5-4553-b31e-dd66c696cebb"),
		"--management-url",
		mgmtURL,
	})
	err = rootCmd.Execute()
	if err != nil && !strings.Contains(err.Error(), "peer login has expired, please log in once more") {
		t.Fatal(err)
	}
}
