package server

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/upload-server/types"
)

const (
	defaultDir = "/var/lib/netbird"
	putHandler = "/{dir}/{file}"
)

type local struct {
	url string
	dir string
}

func configureLocalHandlers(mux *http.ServeMux) error {
	envURL, ok := os.LookupEnv("SERVER_URL")
	if !ok {
		return fmt.Errorf("SERVER_URL environment variable is required")
	}
	_, err := url.Parse(envURL)
	if err != nil {
		return fmt.Errorf("SERVER_URL environment variable is invalid: %w", err)
	}

	dir := defaultDir
	envDir, ok := os.LookupEnv("STORE_DIR")
	if ok {
		if !filepath.IsAbs(envDir) {
			return fmt.Errorf("STORE_DIR environment variable should point to an absolute path, e.g. /tmp")
		}
		log.Infof("Using local directory: %s", envDir)
		dir = envDir
	}

	l := &local{
		url: envURL,
		dir: dir,
	}
	mux.HandleFunc(types.GetURLPath, l.handlerGetUploadURL)
	mux.HandleFunc(putURLPath+putHandler, l.handlePutRequest)

	return nil
}

func (l *local) handlerGetUploadURL(w http.ResponseWriter, r *http.Request) {
	if !isValidRequest(w, r) {
		return
	}

	objectKey := getObjectKey(w, r)
	if objectKey == "" {
		return
	}

	uploadURL, err := l.getUploadURL(objectKey)
	if err != nil {
		http.Error(w, "failed to get upload URL", http.StatusInternalServerError)
		log.Errorf("Failed to get upload URL: %v", err)
		return
	}

	respondGetRequest(w, uploadURL, objectKey)
}

// getUploadURL constructs the upload URL for a given object key.
// Security: This function validates the object key and URL construction to prevent
// URL manipulation attacks and ensure safe URL generation.
func (l *local) getUploadURL(objectKey string) (string, error) {
	// Security: Validate object key is not empty
	if objectKey == "" {
		return "", fmt.Errorf("object key cannot be empty")
	}
	
	// Security: Validate object key length to prevent DoS
	const maxObjectKeyLength = 1024
	if len(objectKey) > maxObjectKeyLength {
		return "", fmt.Errorf("object key too long: maximum length is %d characters", maxObjectKeyLength)
	}
	
	// Security: Validate object key doesn't contain dangerous characters
	// This prevents URL manipulation attacks
	if strings.Contains(objectKey, "..") || strings.Contains(objectKey, "//") {
		return "", fmt.Errorf("invalid object key: contains dangerous characters")
	}
	
	parsedUploadURL, err := url.Parse(l.url)
	if err != nil {
		return "", fmt.Errorf("failed to parse upload URL: %w", err)
	}
	
	// Security: Validate the parsed URL is valid
	if parsedUploadURL.Scheme == "" {
		return "", fmt.Errorf("invalid upload URL: missing scheme")
	}
	
	newURL := parsedUploadURL.JoinPath(parsedUploadURL.Path, putURLPath, objectKey)
	return newURL.String(), nil
}

// handlePutRequest handles file upload requests.
// Security: This function enforces size limits and validates file paths to prevent
// DoS attacks and path traversal vulnerabilities.
func (l *local) handlePutRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Security: Limit request body size to prevent DoS attacks
	// 100MB is a reasonable limit for file uploads
	const maxUploadSize = 100 * 1024 * 1024 // 100MB
	
	// Limit the request body size
	limitedReader := io.LimitReader(r.Body, maxUploadSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		log.Errorf("Failed to read upload body: %v", err)
		return
	}
	
	// Check if body exceeded the size limit
	if len(body) > maxUploadSize {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	uploadDir := r.PathValue("dir")
	if uploadDir == "" {
		http.Error(w, "missing dir path", http.StatusBadRequest)
		return
	}
	uploadFile := r.PathValue("file")
	if uploadFile == "" {
		http.Error(w, "missing file name", http.StatusBadRequest)
		return
	}

	// Security: Validate and sanitize directory and file names to prevent path traversal
	// Remove any path traversal attempts (../, ..\, etc.)
	if strings.Contains(uploadDir, "..") || strings.Contains(uploadFile, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		log.Warnf("Path traversal attempt detected: dir=%s, file=%s", uploadDir, uploadFile)
		return
	}
	
	// Validate that directory and file names don't contain path separators
	if strings.Contains(uploadDir, string(filepath.Separator)) || 
	   strings.Contains(uploadFile, string(filepath.Separator)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	dirPath := filepath.Join(l.dir, uploadDir)
	// Security: Ensure the resolved path is still within the base directory
	// This prevents path traversal attacks even if validation above fails
	absDirPath, err := filepath.Abs(dirPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	absBaseDir, err := filepath.Abs(l.dir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(absDirPath, absBaseDir) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		log.Warnf("Path traversal attempt: resolved path %s is outside base dir %s", absDirPath, absBaseDir)
		return
	}
	
	err = os.MkdirAll(dirPath, 0750)
	if err != nil {
		http.Error(w, "failed to create upload dir", http.StatusInternalServerError)
		log.Errorf("Failed to create upload dir: %v", err)
		return
	}

	file := filepath.Join(dirPath, uploadFile)
	
	// Security: Validate the final file path is within the base directory
	absFilePath, err := filepath.Abs(file)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(absFilePath, absBaseDir) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		log.Warnf("Path traversal attempt: file path %s is outside base dir %s", absFilePath, absBaseDir)
		return
	}
	
	if err := os.WriteFile(file, body, 0600); err != nil {
		http.Error(w, "failed to write file", http.StatusInternalServerError)
		log.Errorf("Failed to write file %s: %v", file, err)
		return
	}
	log.Infof("Uploading file %s", file)
	w.WriteHeader(http.StatusOK)
}
