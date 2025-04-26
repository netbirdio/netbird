package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/netbirdio/netbird/upload-server/types"
)

func TestAccessS3(t *testing.T) {
	awsEndpoint := "http://127.0.0.1:4566"
	awsRegion := "us-east-1"

	ctx := context.Background()
	containerRequest := testcontainers.ContainerRequest{
		Image:        "localstack/localstack:s3-latest",
		ExposedPorts: []string{"4566:4566/tcp"},
		WaitingFor:   wait.ForLog("Ready"),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
	})
	if err != nil {
		t.Error(err)
	}
	defer func(c testcontainers.Container, ctx context.Context) {
		if err := c.Terminate(ctx); err != nil {
			fmt.Println(err)
		}
	}(c, ctx)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion), config.WithBaseEndpoint(awsEndpoint))
	if err != nil {
		t.Error(err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = cfg.BaseEndpoint
	})

	bucketName := "test"
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &bucketName,
	}); err != nil {
		t.Error(err)
	}

	list, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(list.Buckets), 1)
	assert.Equal(t, *list.Buckets[0].Name, bucketName)

	t.Setenv(bucketVar, bucketName)
	t.Setenv("AWS_REGION", awsRegion)
	t.Setenv("AWS_ENDPOINT_URL", awsEndpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	mux := http.NewServeMux()
	configureS3Handlers(mux)

	req := httptest.NewRequest(http.MethodGet, getURLPath+"?id=test-file", nil)
	req.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var response types.GetURLResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	require.Contains(t, response.URL, "test-file/")
	require.NotEmpty(t, response.Key)
	require.Contains(t, response.Key, "test-file/")
}
