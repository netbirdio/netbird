package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/upload-server/types"
)

const (
	putURLPath = "/upload"
	bucketVar  = "BUCKET"
)

type Server struct {
	srv *http.Server
}

// NewServer creates a new upload server instance.
// Security: This function validates environment variables and server configuration
// to ensure secure defaults and prevent misconfiguration.
func NewServer() *Server {
	address := os.Getenv("SERVER_ADDRESS")
	if address == "" {
		log.Infof("SERVER_ADDRESS environment variable was not set, using 0.0.0.0:8080")
		address = "0.0.0.0:8080"
	} else {
		// Security: Validate the address format
		if _, _, err := net.SplitHostPort(address); err != nil {
			log.Fatalf("invalid SERVER_ADDRESS format: %v, must be in format host:port", err)
		}
	}
	
	mux := http.NewServeMux()
	err := configureMux(mux)
	if err != nil {
		log.Fatalf("Failed to configure server: %v", err)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Security: Configure HTTP server with timeouts to prevent resource exhaustion
	// These timeouts protect against slowloris attacks and hanging connections
	return &Server{
		srv: &http.Server{
			Addr:         address,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,  // Maximum time to read request headers and body
			WriteTimeout: 15 * time.Second,  // Maximum time to write response
			IdleTimeout:  60 * time.Second,  // Maximum time to wait for next request on keep-alive
			// Security: Limit header size to prevent header-based DoS attacks
			MaxHeaderBytes: 1 << 20, // 1MB maximum header size
		},
	}
}

func (s *Server) Start() error {
	log.Infof("Starting upload server on %s", s.srv.Addr)
	return s.srv.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.srv != nil {
		log.Infof("Stopping upload server on %s", s.srv.Addr)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(ctx)
	}
	return nil
}

func configureMux(mux *http.ServeMux) error {
	_, ok := os.LookupEnv(bucketVar)
	if ok {
		return configureS3Handlers(mux)
	} else {
		return configureLocalHandlers(mux)
	}
}

// getObjectKey extracts and validates the object key from the request.
// Security: This function validates the ID parameter to prevent injection attacks
// and ensures the generated object key is safe.
func getObjectKey(w http.ResponseWriter, r *http.Request) string {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id query param required", http.StatusBadRequest)
		return ""
	}

	// Security: Validate ID length to prevent DoS
	const maxIDLength = 256
	if len(id) > maxIDLength {
		http.Error(w, "id query param too long", http.StatusBadRequest)
		return ""
	}
	
	// Security: Validate ID doesn't contain dangerous characters
	// This prevents path traversal and injection attacks
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		http.Error(w, "invalid id query param", http.StatusBadRequest)
		return ""
	}
	
	// Security: Validate ID format (alphanumeric, dash, underscore only)
	idRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !idRegex.MatchString(id) {
		http.Error(w, "invalid id query param format", http.StatusBadRequest)
		return ""
	}

	return id + "/" + uuid.New().String()
}

func isValidRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	if r.Header.Get(types.ClientHeader) != types.ClientHeaderValue {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
func respondGetRequest(w http.ResponseWriter, uploadURL string, objectKey string) {
	response := types.GetURLResponse{
		URL: uploadURL,
		Key: objectKey,
	}

	rdata, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		log.Errorf("Marshal error: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(rdata)
	if err != nil {
		log.Errorf("Write error: %v", err)
	}
}
