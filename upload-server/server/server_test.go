package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/netbirdio/netbird/upload-server/server"
	uploadtypes "github.com/netbirdio/netbird/upload-server/types"
)

func Test_UploadServerWithLocalstack(t *testing.T) {
	// Start LocalStack container
	ctx := context.Background()
	localstack, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "localstack/localstack:latest",
			ExposedPorts: []string{"4525/tcp"},
			Env: map[string]string{
				"SERVICES": "s3",
				"SSL_ON":   "0",
			},
			WaitingFor: wait.ForLog("Ready."),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer localstack.Terminate(ctx)

	// Get LocalStack endpoint
	endpoint, err := localstack.Endpoint(ctx, "")
	require.NoError(t, err)

	// Set environment variables for the server
	os.Setenv("BUCKET", "test-bucket")
	os.Setenv("AWS_REGION", "us-east-1")
	os.Setenv("SERVER_ADDRESS", "127.0.0.1:8080")

	// Create S3 client pointing to LocalStack
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithEndpointResolver(aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			return aws.Endpoint{URL: endpoint}, nil
		})),
	)
	require.NoError(t, err)

	s3Client := s3.NewFromConfig(cfg)

	// Create the test bucket
	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String("test-bucket"),
	})
	require.NoError(t, err)

	// Start the server
	srv := server.NewServer()
	go func() {
		err := srv.Start()
		require.NoError(t, err)
	}()
	time.Sleep(2 * time.Second) // Wait for the server to start

	// Test the /upload-url endpoint
	t.Run("GenerateUploadURL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/upload-url?id=test-file", nil)
		req.Header.Set(uploadtypes.ClientHeader, uploadtypes.ClientHeaderValue)

		rec := httptest.NewRecorder()
		//srv.Handler().ServeHTTP(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		var response uploadtypes.GetURLResponse
		err = json.Unmarshal(body, &response)
		require.NoError(t, err)

		require.Contains(t, response.URL, "test-bucket")
		require.Contains(t, response.Key, "test-file/")
		require.NotEmpty(t, response.Key)

		// Verify the presigned URL works
		_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(response.Key),
		})
		require.NoError(t, err)
	})
}
