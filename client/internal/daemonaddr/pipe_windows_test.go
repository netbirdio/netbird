//go:build windows

package daemonaddr

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A denied first path and a missing second path must return the denial.
func TestDialPipePaths_PrefersAccessDenied(t *testing.T) {
	base := fmt.Sprintf(`\\.\pipe\netbird-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	denied := base + "-denied"

	// An empty DACL denies everyone.
	ln, err := winio.ListenPipe(denied, &winio.PipeConfig{SecurityDescriptor: "D:P"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = dialPipePaths(ctx, []string{denied, base + "-missing"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, fs.ErrPermission), "want the access-denied error, got %v", err)
	assert.True(t, DeniesCaller(context.Background(), "npipe://"+denied), "a pipe whose DACL refuses the caller must report a denial")
}

func TestDialPipePaths_MissingIsNotDenied(t *testing.T) {
	missing := fmt.Sprintf(`\\.\pipe\netbird-test-%d-%d-missing`, os.Getpid(), time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dialPipePaths(ctx, []string{missing})
	require.Error(t, err)
	assert.False(t, errors.Is(err, fs.ErrPermission), "a missing pipe is not a denial: %v", err)
	assert.False(t, DeniesCaller(context.Background(), "npipe://"+missing), "a stopped daemon is not a denial")
}
