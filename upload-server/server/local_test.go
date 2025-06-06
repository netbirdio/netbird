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

func Test_LocalHandlerGetUploadURL(t *testing.T) {
	mockURL := "http://localhost:8080"
	t.Setenv("SERVER_URL", mockURL)
	t.Setenv("STORE_DIR", t.TempDir())

	mux := http.NewServeMux()
	err := configureLocalHandlers(mux)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, types.GetURLPath+"?id=test-file", nil)
	req.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var response types.GetURLResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	require.Contains(t, response.URL, "test-file/")
	require.NotEmpty(t, response.Key)
	require.Contains(t, response.Key, "test-file/")

}

func Test_LocalHandlerGetUploadURL_WithPath(t *testing.T) {
       mockURL := "http://localhost:8080/api"
       t.Setenv("SERVER_URL", mockURL)
       t.Setenv("STORE_DIR", t.TempDir())

       mux := http.NewServeMux()
       err := configureLocalHandlers(mux)
       require.NoError(t, err)

       req := httptest.NewRequest(http.MethodGet, types.GetURLPath+"?id=testfile", nil)
       req.Header.Set(types.ClientHeader, types.ClientHeaderValue)

       rec := httptest.NewRecorder()
       mux.ServeHTTP(rec, req)

       require.Equal(t, http.StatusOK, rec.Code)

       var response types.GetURLResponse
       err = json.Unmarshal(rec.Body.Bytes(), &response)
       require.NoError(t, err)
       expected := "/api" + putURLPath + "/testfile/"
       require.Contains(t, response.URL, expected)
}

func Test_LocalHandlePutRequest(t *testing.T) {
	mockDir := t.TempDir()
	mockURL := "http://localhost:8080"
	t.Setenv("SERVER_URL", mockURL)
	t.Setenv("STORE_DIR", mockDir)

	mux := http.NewServeMux()
	err := configureLocalHandlers(mux)
	require.NoError(t, err)

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
