package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/types"
)

func Test_HandlerGetUploadURL(t *testing.T) {
	mockURL := "http://localhost:8080"
	l := &local{
		url: mockURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(getURLPath, l.handlerGetUploadURL)

	req := httptest.NewRequest(http.MethodGet, getURLPath+"?id=test-file", nil)
	req.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var response types.GetURLResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	require.Contains(t, response.URL, "test-file/")
	require.NotEmpty(t, response.Key)
	require.Contains(t, response.Key, "test-file/")

}

func Test_HandlePutRequest(t *testing.T) {
	mockDir := t.TempDir()
	l := &local{
		dir: mockDir,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(putURLPath+putHandler, l.handlePutRequest)

	fileContent := []byte("test file content")
	req := httptest.NewRequest(http.MethodPut, putURLPath+"/uploads/test.txt", bytes.NewReader(fileContent))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	expectedFilePath := filepath.Join(mockDir, "uploads", "test.txt")
	createdFileContent, err := os.ReadFile(expectedFilePath)
	require.NoError(t, err)
	require.Equal(t, fileContent, createdFileContent)
}
