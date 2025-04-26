package server

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

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
		return fmt.Errorf("SERVER_URL environment variable is invalid: %v", err)
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
		return "", fmt.Errorf("failed to parse upload URL: %v", err)
	}
	newURL := parsedUploadURL.JoinPath(parsedUploadURL.Path, putURLPath, objectKey)
	return newURL.String(), nil
}

func (l *local) handlePutRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusInternalServerError)
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

	dirPath := filepath.Join(l.dir, uploadDir)
	err = os.MkdirAll(dirPath, 0750)
	if err != nil {
		http.Error(w, "failed to create upload dir", http.StatusInternalServerError)
		log.Errorf("Failed to create upload dir: %v", err)
		return
	}

	file := filepath.Join(dirPath, uploadFile)
	if err := os.WriteFile(file, body, 0600); err != nil {
		log.Fatal(err)
	}
	log.Infof("Uploading file %s", file)
	w.WriteHeader(http.StatusOK)
}
