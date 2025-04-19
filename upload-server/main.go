package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

func main() {
	ctx := context.Background()

	bucket := os.Getenv("BUCKET")
	if bucket == "" {
		log.Fatalf("BUCKET environment variable is required")
	}
	region := os.Getenv("REGION")
	if region == "" {
		log.Fatalf("REGION environment variable is required")
	}

	// Load AWS credentials and region from environment or shared config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("Unable to load SDK config: %v", err)
	}

	client := s3.NewFromConfig(cfg)

	http.HandleFunc("/upload-url", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "filename query param required", http.StatusBadRequest)
			return
		}

		objectKey := id + "/" + uuid.New().String()

		psClient := s3.NewPresignClient(client)

		req, err := psClient.PresignPutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(objectKey),
		}, s3.WithPresignExpires(15*time.Minute))

		if err != nil {
			http.Error(w, "failed to presign URL", http.StatusInternalServerError)
			log.Println("Presign error:", err)
			return
		}

		type Response struct {
			URL string `json:"url"`
			Key string `json:"key"`
		}

		response := Response{
			URL: req.URL,
			Key: objectKey,
		}

		rdata, err := json.Marshal(response)

		w.WriteHeader(http.StatusOK)
		w.Write(rdata)
	})

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
