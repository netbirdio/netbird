package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	log "github.com/sirupsen/logrus"
)

type sThree struct {
	ctx           context.Context
	bucket        string
	presignClient *s3.PresignClient
}

func configureS3Handlers(mux *http.ServeMux) error {
	bucket := os.Getenv(bucketVar)
	region, ok := os.LookupEnv("AWS_REGION")
	if !ok {
		return fmt.Errorf("AWS_REGION environment variable is required")
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("unable to load SDK config: %v", err)
	}

	client := s3.NewFromConfig(cfg)

	handler := &sThree{
		ctx:           ctx,
		bucket:        bucket,
		presignClient: s3.NewPresignClient(client),
	}
	mux.HandleFunc(getURLPath, handler.handlerGetUploadURL)
	return nil
}

func (s *sThree) handlerGetUploadURL(w http.ResponseWriter, r *http.Request) {
	if !isValidRequest(w, r) {
		return
	}

	objectKey := getObjectKey(w, r)
	if objectKey == "" {
		return
	}

	req, err := s.presignClient.PresignPutObject(s.ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	}, s3.WithPresignExpires(15*time.Minute))

	if err != nil {
		http.Error(w, "failed to presign URL", http.StatusInternalServerError)
		log.Errorf("Presign error: %v", err)
		return
	}

	respondGetRequest(w, req.URL, objectKey)
}
