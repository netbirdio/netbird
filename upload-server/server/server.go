package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/upload-server/types"
)

const (
	putURLPath = "/upload"
	bucketVar  = "BUCKET"

	// certFileVar and keyFileVar enable TLS. A client refuses a plaintext
	// upload service — it asks this server for an upload URL and then PUTs the
	// bundle to whatever comes back, so a plaintext hop is a place to intercept
	// both — which leaves an operator running this server needing TLS. Without
	// these the server stays plaintext, for a deployment that terminates TLS in
	// front of it.
	certFileVar = "SERVER_CERT_FILE"
	keyFileVar  = "SERVER_KEY_FILE"
)

type Server struct {
	srv      *http.Server
	certFile string
	keyFile  string
}

func NewServer() *Server {
	address := os.Getenv("SERVER_ADDRESS")
	if address == "" {
		log.Infof("SERVER_ADDRESS environment variable was not set, using 0.0.0.0:8080")
		address = "0.0.0.0:8080"
	}
	mux := http.NewServeMux()
	err := configureMux(mux)
	if err != nil {
		log.Fatalf("Failed to configure server: %v", err)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	certFile := os.Getenv(certFileVar)
	keyFile := os.Getenv(keyFileVar)
	if (certFile == "") != (keyFile == "") {
		log.Fatalf("%s and %s must be set together", certFileVar, keyFileVar)
	}

	return &Server{
		srv:      &http.Server{Addr: address, Handler: mux},
		certFile: certFile,
		keyFile:  keyFile,
	}
}

func (s *Server) Start() error {
	if s.certFile != "" {
		log.Infof("Starting upload server on %s with TLS", s.srv.Addr)
		return s.srv.ListenAndServeTLS(s.certFile, s.keyFile)
	}

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

func getObjectKey(w http.ResponseWriter, r *http.Request) string {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id query param required", http.StatusBadRequest)
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
