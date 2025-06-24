//go:build unix

package server

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivilegeDropper_ValidatePrivileges(t *testing.T) {
	pd := NewPrivilegeDropper()

	tests := []struct {
		name    string
		uid     uint32
		gid     uint32
		wantErr bool
	}{
		{
			name:    "valid non-root user",
			uid:     1000,
			gid:     1000,
			wantErr: false,
		},
		{
			name:    "root UID should be rejected",
			uid:     0,
			gid:     1000,
			wantErr: true,
		},
		{
			name:    "root GID should be rejected",
			uid:     1000,
			gid:     0,
			wantErr: true,
		},
		{
			name:    "both root should be rejected",
			uid:     0,
			gid:     0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pd.validatePrivileges(tt.uid, tt.gid)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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

// TestPrivilegeDropper_ActualPrivilegeDrop tests actual privilege dropping
// This test requires root privileges and will be skipped if not running as root
func TestPrivilegeDropper_ActualPrivilegeDrop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Privilege dropping not supported on Windows")
	}

	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Find a non-root user to test with
	testUser, err := user.Lookup("nobody")
	if err != nil {
		// Try to find any non-root user
		testUser, err = findNonRootUser()
		if err != nil {
			t.Skip("No suitable non-root user found for testing")
		}
	}

	uid64, err := strconv.ParseUint(testUser.Uid, 10, 32)
	require.NoError(t, err)
	targetUID := uint32(uid64)

	gid64, err := strconv.ParseUint(testUser.Gid, 10, 32)
	require.NoError(t, err)
	targetGID := uint32(gid64)

	// Test in a child process to avoid affecting the test runner
	if os.Getenv("TEST_PRIVILEGE_DROP") == "1" {
		pd := NewPrivilegeDropper()

		// This should succeed
		err := pd.DropPrivileges(targetUID, targetGID, []uint32{targetGID})
		require.NoError(t, err)

		// Verify we are now running as the target user
		currentUID := uint32(os.Geteuid())
		currentGID := uint32(os.Getegid())

		assert.Equal(t, targetUID, currentUID, "UID should match target")
		assert.Equal(t, targetGID, currentGID, "GID should match target")
		assert.NotEqual(t, uint32(0), currentUID, "Should not be running as root")
		assert.NotEqual(t, uint32(0), currentGID, "Should not be running as root group")

		return
	}

	// Fork a child process to test privilege dropping
	cmd := os.Args[0]
	args := []string{"-test.run=TestPrivilegeDropper_ActualPrivilegeDrop"}

	env := append(os.Environ(), "TEST_PRIVILEGE_DROP=1")

	execCmd := exec.Command(cmd, args...)
	execCmd.Env = env

	err = execCmd.Run()
	require.NoError(t, err, "Child process should succeed")
}

// findNonRootUser finds any non-root user on the system for testing
func findNonRootUser() (*user.User, error) {
	// Try common non-root users
	commonUsers := []string{"nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc"}

	for _, username := range commonUsers {
		if u, err := user.Lookup(username); err == nil {
			uid64, err := strconv.ParseUint(u.Uid, 10, 32)
			if err != nil {
				continue
			}
			if uid64 != 0 { // Not root
				return u, nil
			}
		}
	}

	// If no common users found, create a minimal user info for testing
	// This won't actually work for privilege dropping but allows the test structure
	return &user.User{
		Uid:      "65534", // Standard nobody UID
		Gid:      "65534", // Standard nobody GID
		Username: "nobody",
		Name:     "nobody",
		HomeDir:  "/nonexistent",
	}, nil
}

func TestPrivilegeDropper_ExecuteWithPrivilegeDrop_Validation(t *testing.T) {
	pd := NewPrivilegeDropper()

	// Test validation of root privileges - this should be caught in CreateExecutorCommand
	config := ExecutorConfig{
		UID:        0, // Root UID should be rejected
		GID:        1000,
		Groups:     []uint32{1000},
		WorkingDir: "/tmp",
		Shell:      "/bin/sh",
		Command:    "echo test",
	}

	_, err := pd.CreateExecutorCommand(context.Background(), config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "root user")
}
