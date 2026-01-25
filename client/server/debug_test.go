package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/server"
	"github.com/netbirdio/netbird/upload-server/types"
)

// waitForServer waits for the server to be ready by polling the health endpoint.
func waitForServer(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready within %v", timeout)
}

func TestUpload(t *testing.T) {
	if os.Getenv("DOCKER_CI") == "true" {
		t.Skip("Skipping upload test on docker ci")
	}
	testDir := t.TempDir()
	testURL := "http://localhost:8080"
	t.Setenv("SERVER_URL", testURL)
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

	// Wait for the server to be ready before proceeding with the test
	err := waitForServer(testURL, 5*time.Second)
	require.NoError(t, err, "Server did not start in time")

	file := filepath.Join(t.TempDir(), "tmpfile")
	fileContent := []byte("test file content")
	err = os.WriteFile(file, fileContent, 0640)
	require.NoError(t, err)
	key, err := uploadDebugBundle(context.Background(), testURL+types.GetURLPath, testURL, file)
	require.NoError(t, err)
	id := getURLHash(testURL)
	require.Contains(t, key, id+"/")
	expectedFilePath := filepath.Join(testDir, key)
	createdFileContent, err := os.ReadFile(expectedFilePath)
	require.NoError(t, err)
	require.Equal(t, fileContent, createdFileContent)
}
