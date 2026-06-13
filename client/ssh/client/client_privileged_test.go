//go:build privileged

package client

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/ssh/testutil"
)

func TestSSHClient_CommandExecution(t *testing.T) {
	if runtime.GOOS == "windows" && testutil.IsCI() {
		t.Skip("Skipping Windows command execution tests in CI due to S4U authentication issues")
	}

	server, _, client := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()
	defer func() {
		err := client.Close()
		assert.NoError(t, err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	t.Run("ExecuteCommand captures output", func(t *testing.T) {
		output, err := client.ExecuteCommand(ctx, "echo hello")
		assert.NoError(t, err)
		assert.Contains(t, string(output), "hello")
	})

	t.Run("ExecuteCommandWithIO streams output", func(t *testing.T) {
		err := client.ExecuteCommandWithIO(ctx, "echo world")
		assert.NoError(t, err)
	})

	t.Run("commands with flags work", func(t *testing.T) {
		output, err := client.ExecuteCommand(ctx, "echo -n test_flag")
		assert.NoError(t, err)
		assert.Equal(t, "test_flag", strings.TrimSpace(string(output)))
	})

	t.Run("non-zero exit codes don't return errors", func(t *testing.T) {
		var testCmd string
		if runtime.GOOS == "windows" {
			testCmd = "echo hello | Select-String notfound"
		} else {
			testCmd = "echo 'hello' | grep 'notfound'"
		}
		_, err := client.ExecuteCommand(ctx, testCmd)
		assert.NoError(t, err)
	})
}

func TestSSHClient_ContextCancellation(t *testing.T) {
	server, serverAddr, _ := setupTestSSHServerAndClient(t)
	defer func() {
		err := server.Stop()
		require.NoError(t, err)
	}()

	t.Run("connection with short timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		currentUser := testutil.GetTestUsername(t)
		_, err := Dial(ctx, serverAddr, currentUser, DialOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			// Check for actual timeout-related errors rather than string matching
			assert.True(t,
				errors.Is(err, context.DeadlineExceeded) ||
					errors.Is(err, context.Canceled) ||
					strings.Contains(err.Error(), "timeout"),
				"Expected timeout-related error, got: %v", err)
		}
	})

	t.Run("command execution cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		currentUser := testutil.GetTestUsername(t)
		client, err := Dial(ctx, serverAddr, currentUser, DialOptions{
			InsecureSkipVerify: true,
		})
		require.NoError(t, err)
		defer func() {
			if err := client.Close(); err != nil {
				t.Logf("client close error: %v", err)
			}
		}()

		cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cmdCancel()

		err = client.ExecuteCommandWithPTY(cmdCtx, "sleep 10")
		if err != nil {
			var exitMissingErr *cryptossh.ExitMissingError
			isValidCancellation := errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, context.Canceled) ||
				errors.As(err, &exitMissingErr)
			assert.True(t, isValidCancellation, "Should handle command cancellation properly")
		}
	})
}
