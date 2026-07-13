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

func (l *local) getUploadURL(objectKey string) (string, error) {
	parsedUploadURL, err := url.Parse(l.url)
	if err != nil {
		return "", fmt.Errorf("failed to parse upload URL: %w", err)
	}
	newURL := parsedUploadURL.JoinPath(parsedUploadURL.Path, putURLPath, objectKey)
	return newURL.String(), nil
}

const maxUploadSize = 150 << 20

func (l *local) handlePutRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or failed to read", http.StatusRequestEntityTooLarge)
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

	cleanBase := filepath.Clean(l.dir) + string(filepath.Separator)

	dirPath := filepath.Clean(filepath.Join(l.dir, uploadDir))
	if !strings.HasPrefix(dirPath, cleanBase) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		log.Warnf("Path traversal attempt blocked (dir): %s", dirPath)
		return
	}

	filePath := filepath.Clean(filepath.Join(dirPath, uploadFile))
	if !strings.HasPrefix(filePath, cleanBase) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		log.Warnf("Path traversal attempt blocked (file): %s", filePath)
		return
	}

	if err = os.MkdirAll(dirPath, 0750); err != nil {
		http.Error(w, "failed to create upload dir", http.StatusInternalServerError)
		log.Errorf("Failed to create upload dir: %v", err)
		return
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	f, err := os.OpenFile(filePath, flags, 0600)
	if err != nil {
		if os.IsExist(err) {
			http.Error(w, "file already exists", http.StatusConflict)
			return
		}
		http.Error(w, "failed to create file", http.StatusInternalServerError)
		log.Errorf("Failed to create file %s: %v", filePath, err)
		return
	}
	defer func() { _ = f.Close() }()

	if _, err = f.Write(body); err != nil {
		http.Error(w, "failed to write file", http.StatusInternalServerError)
		log.Errorf("Failed to write file %s: %v", filePath, err)
		return
	}

	log.Infof("Uploaded file %s", filePath)
	w.WriteHeader(http.StatusOK)
}
