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

func Test_LocalHandlePutRequest_PathTraversal(t *testing.T) {
	mockDir := t.TempDir()
	mockURL := "http://localhost:8080"
	t.Setenv("SERVER_URL", mockURL)
	t.Setenv("STORE_DIR", mockDir)

	mux := http.NewServeMux()
	err := configureLocalHandlers(mux)
	require.NoError(t, err)

	fileContent := []byte("malicious content")
	req := httptest.NewRequest(http.MethodPut, putURLPath+"/uploads/%2e%2e%2f%2e%2e%2fetc%2fpasswd", bytes.NewReader(fileContent))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)

	_, err = os.Stat(filepath.Join(mockDir, "..", "..", "etc", "passwd"))
	require.True(t, os.IsNotExist(err), "traversal file should not exist")
}

func Test_LocalHandlePutRequest_DirTraversal(t *testing.T) {
	mockDir := t.TempDir()
	t.Setenv("SERVER_URL", "http://localhost:8080")
	t.Setenv("STORE_DIR", mockDir)

	l := &local{url: "http://localhost:8080", dir: mockDir}

	body := bytes.NewReader([]byte("bad"))
	req := httptest.NewRequest(http.MethodPut, putURLPath+"/x/evil.txt", body)
	req.SetPathValue("dir", "../../../tmp")
	req.SetPathValue("file", "evil.txt")

	rec := httptest.NewRecorder()
	l.handlePutRequest(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)

	_, err := os.Stat(filepath.Join("/tmp", "evil.txt"))
	require.True(t, os.IsNotExist(err), "traversal file should not exist outside store dir")
}

func Test_LocalHandlePutRequest_DuplicateFile(t *testing.T) {
	mockDir := t.TempDir()
	t.Setenv("SERVER_URL", "http://localhost:8080")
	t.Setenv("STORE_DIR", mockDir)

	mux := http.NewServeMux()
	err := configureLocalHandlers(mux)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, putURLPath+"/dir/dup.txt", bytes.NewReader([]byte("first")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	req = httptest.NewRequest(http.MethodPut, putURLPath+"/dir/dup.txt", bytes.NewReader([]byte("second")))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusConflict, rec.Code)

	content, err := os.ReadFile(filepath.Join(mockDir, "dir", "dup.txt"))
	require.NoError(t, err)
	require.Equal(t, []byte("first"), content)
}

func Test_LocalHandlePutRequest_BodyTooLarge(t *testing.T) {
	mockDir := t.TempDir()
	t.Setenv("SERVER_URL", "http://localhost:8080")
	t.Setenv("STORE_DIR", mockDir)

	mux := http.NewServeMux()
	err := configureLocalHandlers(mux)
	require.NoError(t, err)

	largeBody := make([]byte, maxUploadSize+1)
	req := httptest.NewRequest(http.MethodPut, putURLPath+"/dir/big.txt", bytes.NewReader(largeBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	_, err = os.Stat(filepath.Join(mockDir, "dir", "big.txt"))
	require.True(t, os.IsNotExist(err))
}
