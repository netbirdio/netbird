package debug

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/server"
	"github.com/netbirdio/netbird/upload-server/types"
)

func TestUpload(t *testing.T) {
	if os.Getenv("DOCKER_CI") == "true" {
		t.Skip("Skipping upload test on docker ci")
	}
	testDir := t.TempDir()
	addr := reserveLoopbackPort(t)
	testURL := "http://" + addr
	t.Setenv("SERVER_URL", testURL)
	t.Setenv("SERVER_ADDRESS", addr)
	t.Setenv("STORE_DIR", testDir)
	srv := server.NewServer()
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Failed to start server: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	})
	waitForServer(t, addr)

	file := filepath.Join(t.TempDir(), "tmpfile")
	fileContent := []byte("test file content")
	err := os.WriteFile(file, fileContent, 0640)
	require.NoError(t, err)
	key, err := UploadDebugBundle(context.Background(), testURL+types.GetURLPath, testURL, file)
	require.NoError(t, err)
	id := getURLHash(testURL)
	require.Contains(t, key, id+"/")
	expectedFilePath := filepath.Join(testDir, key)
	createdFileContent, err := os.ReadFile(expectedFilePath)
	require.NoError(t, err)
	require.Equal(t, fileContent, createdFileContent)
}

// reserveLoopbackPort binds an ephemeral port on loopback to learn a free
// address, then releases it so the server under test can rebind. The close/
// rebind window is racy in theory; on loopback with a kernel-assigned port
// it's essentially never contended in practice.
func reserveLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s in time", addr)
}
