//go:build unix

package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivilegeDropper_ValidatePrivileges(t *testing.T) {
	pd := NewPrivilegeDropper(nil)

	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())

	tests := []struct {
		name    string
		uid     uint32
		gid     uint32
		wantErr bool
	}{
		{
			name:    "same user - no privilege drop needed",
			uid:     currentUID,
			gid:     currentGID,
			wantErr: false,
		},
		{
			name:    "non-root to different user should fail",
			uid:     currentUID + 1,  // Use a different UID to ensure it's actually different
			gid:     currentGID + 1,  // Use a different GID to ensure it's actually different
			wantErr: currentUID != 0, // Only fail if current user is not root
		},
		{
			name:    "root can drop to any user",
			uid:     1000,
			gid:     1000,
			wantErr: false,
		},
		{
			name:    "root can stay as root",
			uid:     0,
			gid:     0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip non-root tests when running as root, and root tests when not root
			if tt.name == "non-root to different user should fail" && currentUID == 0 {
				t.Skip("Skipping non-root test when running as root")
			}
			if (tt.name == "root can drop to any user" || tt.name == "root can stay as root") && currentUID != 0 {
				t.Skip("Skipping root test when not running as root")
			}

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
	pd := NewPrivilegeDropper(nil)

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
	pd := NewPrivilegeDropper(nil)

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
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Find a non-root user to test with
	testUser, err := findNonRootUser()
	if err != nil {
		t.Skip("No suitable non-root user found for testing")
	}

	// Verify the user actually exists by looking it up again
	_, err = user.LookupId(testUser.Uid)
	if err != nil {
		t.Skipf("Test user %s (UID %s) does not exist on this system: %v", testUser.Username, testUser.Uid, err)
	}

	uid64, err := strconv.ParseUint(testUser.Uid, 10, 32)
	require.NoError(t, err)
	targetUID := uint32(uid64)

	gid64, err := strconv.ParseUint(testUser.Gid, 10, 32)
	require.NoError(t, err)
	targetGID := uint32(gid64)

	// Test in a child process to avoid affecting the test runner
	if os.Getenv("TEST_PRIVILEGE_DROP") == "1" {
		pd := NewPrivilegeDropper(nil)

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
	// Try common non-root users, but avoid "nobody" on macOS due to negative UID issues
	commonUsers := []string{"daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc"}

	for _, username := range commonUsers {
		if u, err := user.Lookup(username); err == nil {
			// Parse as signed integer first to handle negative UIDs
			uid64, err := strconv.ParseInt(u.Uid, 10, 32)
			if err != nil {
				continue
			}
			// Skip negative UIDs (like nobody=-2 on macOS) and root
			if uid64 > 0 && uid64 != 0 {
				return u, nil
			}
		}
	}

	// If no common users found, try to find any regular user with UID > 100
	// This helps on macOS where regular users start at UID 501
	allUsers := []string{"vma", "user", "test", "admin"}
	for _, username := range allUsers {
		if u, err := user.Lookup(username); err == nil {
			uid64, err := strconv.ParseInt(u.Uid, 10, 32)
			if err != nil {
				continue
			}
			if uid64 > 100 { // Regular user
				return u, nil
			}
		}
	}

	// If no common users found, return an error
	return nil, fmt.Errorf("no suitable non-root user found on this system")
}

func TestPrivilegeDropper_ExecuteWithPrivilegeDrop_Validation(t *testing.T) {
	pd := NewPrivilegeDropper(nil)
	currentUID := uint32(os.Geteuid())

	if currentUID == 0 {
		// When running as root, test that root can create commands for any user
		config := ExecutorConfig{
			UID:        1000, // Target non-root user
			GID:        1000,
			Groups:     []uint32{1000},
			WorkingDir: "/tmp",
			Shell:      "/bin/sh",
			Command:    "echo test",
		}

		cmd, err := pd.CreateExecutorCommand(context.Background(), config)
		assert.NoError(t, err, "Root should be able to create commands for any user")
		assert.NotNil(t, cmd)
	} else {
		// When running as non-root, test that we can't drop to a different user
		config := ExecutorConfig{
			UID:        0, // Try to target root
			GID:        0,
			Groups:     []uint32{0},
			WorkingDir: "/tmp",
			Shell:      "/bin/sh",
			Command:    "echo test",
		}

		_, err := pd.CreateExecutorCommand(context.Background(), config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot drop privileges")
	}
}
