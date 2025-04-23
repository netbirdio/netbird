package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/upload-server/types"
)

type Server struct {
	ctx           context.Context
	address       string
	bucket        string
	presignClient *s3.PresignClient
	mux           *http.ServeMux
}

func NewServer() *Server {
	bucket := os.Getenv("BUCKET")
	if bucket == "" {
		log.Fatalf("BUCKET environment variable is required")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		log.Fatalf("AWS_REGION environment variable is required")
	}

	address := os.Getenv("SERVER_ADDRESS")
	if address == "" {
		log.Infof("SERVER_ADDRESS environment variable was not set, using 0.0.0.0:8080")
		address = "0.0.0.0:8080"
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("Unable to load SDK config: %v", err)
	}

	client := s3.NewFromConfig(cfg)

	srv := &Server{
		ctx:           ctx,
		address:       address,
		bucket:        bucket,
		presignClient: s3.NewPresignClient(client),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/upload-url", srv.handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv.mux = mux
	return srv
}

func (s *Server) Start() error {
	log.Infof("Starting upload server on %s", s.address)
	return http.ListenAndServe(s.address, s.mux)
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(types.ClientHeader) != types.ClientHeaderValue {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "filename query param required", http.StatusBadRequest)
		return
	}

	objectKey := id + "/" + uuid.New().String()

	req, err := s.presignClient.PresignPutObject(s.ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	}, s3.WithPresignExpires(15*time.Minute))

	if err != nil {
		http.Error(w, "failed to presign URL", http.StatusInternalServerError)
		log.Errorf("Presign error: %v", err)
		return
	}

	response := types.GetURLResponse{
		URL: req.URL,
		Key: objectKey,
	}

	rdata, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		log.Errorf("Marshal error: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(rdata)
}
