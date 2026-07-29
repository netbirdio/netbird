//go:build !ios && !android

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSetSSHConfigArgs(t *testing.T) {
	tr, fa := true, false

	t.Run("enable root only, with daemon-addr", func(t *testing.T) {
		got := buildSetSSHConfigArgs("prof", "alice", &tr, nil, "unix:///x.sock")
		assert.Equal(t, []string{
			SetSSHConfigCmdName, "--profile", "prof", "--username", "alice",
			"--" + enableSSHRootFlag, "--daemon-addr", "unix:///x.sock",
		}, got)
	})

	t.Run("disable auth only, no daemon-addr", func(t *testing.T) {
		got := buildSetSSHConfigArgs("prof", "alice", nil, &tr, "")
		assert.Equal(t, []string{
			SetSSHConfigCmdName, "--profile", "prof", "--username", "alice",
			"--" + disableSSHAuthFlag,
		}, got)
	})

	t.Run("false pointers omit the flags", func(t *testing.T) {
		got := buildSetSSHConfigArgs("", "", &fa, &fa, "")
		assert.Equal(t, []string{SetSSHConfigCmdName}, got)
	})

	t.Run("both enabled", func(t *testing.T) {
		got := buildSetSSHConfigArgs("p", "u", &tr, &tr, "")
		assert.Equal(t, []string{
			SetSSHConfigCmdName, "--profile", "p", "--username", "u",
			"--" + enableSSHRootFlag, "--" + disableSSHAuthFlag,
		}, got)
	})
}

func TestBuildSetSSHConfigRequest(t *testing.T) {
	tr := true

	req := buildSetSSHConfigRequest("p", "u", &tr, nil)
	assert.Equal(t, "p", req.ProfileName)
	assert.Equal(t, "u", req.Username)
	if assert.NotNil(t, req.EnableSSHRoot) {
		assert.True(t, *req.EnableSSHRoot)
	}
	assert.Nil(t, req.DisableSSHAuth, "an unset flag must leave the daemon value untouched")
}

func TestWantsDangerousSSH(t *testing.T) {
	origRoot, origAuth := enableSSHRoot, disableSSHAuth
	t.Cleanup(func() { enableSSHRoot, disableSSHAuth = origRoot, origAuth })

	newCmd := func() *cobra.Command {
		enableSSHRoot, disableSSHAuth = false, false
		c := &cobra.Command{Use: "x"}
		c.Flags().BoolVar(&enableSSHRoot, enableSSHRootFlag, false, "")
		c.Flags().BoolVar(&disableSSHAuth, disableSSHAuthFlag, false, "")
		return c
	}

	// wantsDangerousSSH fires only in the privileged direction.
	t.Run("enable root true is dangerous", func(t *testing.T) {
		c := newCmd()
		require.NoError(t, c.Flags().Set(enableSSHRootFlag, "true"))
		assert.True(t, wantsDangerousSSH(c))
	})

	t.Run("enable root false is not dangerous", func(t *testing.T) {
		c := newCmd()
		require.NoError(t, c.Flags().Set(enableSSHRootFlag, "false"))
		assert.False(t, wantsDangerousSSH(c))
	})

	t.Run("disable auth true is dangerous", func(t *testing.T) {
		c := newCmd()
		require.NoError(t, c.Flags().Set(disableSSHAuthFlag, "true"))
		assert.True(t, wantsDangerousSSH(c))
	})

	t.Run("disable auth false is not dangerous", func(t *testing.T) {
		c := newCmd()
		require.NoError(t, c.Flags().Set(disableSSHAuthFlag, "false"))
		assert.False(t, wantsDangerousSSH(c))
	})

	t.Run("nothing changed is not dangerous", func(t *testing.T) {
		c := newCmd()
		assert.False(t, wantsDangerousSSH(c))
	})
}
