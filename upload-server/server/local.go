package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type local struct {
	dir string
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

	os.MkdirAll(l.dir, 0750)

	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}

	file := filepath.Join(dir, "tmpfile")
	if err := os.WriteFile(file, body, 0666); err != nil {
		log.Fatal(err)
	}
	log.Infof("Uploading file %s", file)
	w.WriteHeader(http.StatusOK)
}
