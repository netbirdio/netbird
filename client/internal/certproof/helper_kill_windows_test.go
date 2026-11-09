//go:build windows

package certproof

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunHelperCmd_KillsHelperTree: the helper's child holds stdout and runs for a minute,
// like a helper stuck below a launcher. Killing only the helper would leave Wait blocked
// on the child's pipe until WaitDelay gives up; terminating the job ends both at once.
func TestRunHelperCmd_KillsHelperTree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cmd.exe", "/c", "ping -n 60 127.0.0.1")

	start := time.Now()
	_, err := runHelperCmd(cmd, HelperRequest{Challenges: []HelperChallenge{{Nonce: []byte("asked")}}})

	require.Error(t, err)
	assert.Less(t, time.Since(start), helperWaitDelay, "the whole tree is killed at the timeout, not left for WaitDelay")
}
