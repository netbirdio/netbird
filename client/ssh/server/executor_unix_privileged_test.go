//go:build unix && privileged

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivilegeDropper_CreateExecutorCommand(t *testing.T) {
	pd := NewPrivilegeDropper()

	config := ExecutorConfig{
		UID:        1000,
		GID:        1000,
		Groups:     []uint32{1000, 1001},
		WorkingDir: "/home/testuser",
		Shell:      "/bin/bash",
		Command:    "ls -la",
	}

	cmd, err := pd.CreateExecutorCommand(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Verify the command is calling netbird ssh exec
	assert.Contains(t, cmd.Args, "ssh")
	assert.Contains(t, cmd.Args, "exec")
	assert.Contains(t, cmd.Args, "--uid")
	assert.Contains(t, cmd.Args, "1000")
	assert.Contains(t, cmd.Args, "--gid")
	assert.Contains(t, cmd.Args, "1000")
	assert.Contains(t, cmd.Args, "--groups")
	assert.Contains(t, cmd.Args, "1000")
	assert.Contains(t, cmd.Args, "1001")
	assert.Contains(t, cmd.Args, "--working-dir")
	assert.Contains(t, cmd.Args, "/home/testuser")
	assert.Contains(t, cmd.Args, "--shell")
	assert.Contains(t, cmd.Args, "/bin/bash")
	assert.Contains(t, cmd.Args, "--cmd")
	assert.Contains(t, cmd.Args, "ls -la")
}

func TestPrivilegeDropper_CreateExecutorCommandInteractive(t *testing.T) {
	pd := NewPrivilegeDropper()

	config := ExecutorConfig{
		UID:        1000,
		GID:        1000,
		Groups:     []uint32{1000},
		WorkingDir: "/home/testuser",
		Shell:      "/bin/bash",
		Command:    "",
	}

	cmd, err := pd.CreateExecutorCommand(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Verify no command mode (command is empty so no --cmd flag)
	assert.NotContains(t, cmd.Args, "--cmd")
	assert.NotContains(t, cmd.Args, "--interactive")
}
