package debug

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/server"
	"github.com/netbirdio/netbird/upload-server/types"
)

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
