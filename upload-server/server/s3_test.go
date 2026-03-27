package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/netbirdio/netbird/upload-server/types"
)

func Test_S3HandlerGetUploadURL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping test on non-Linux due to docker dependency")
	}

	awsRegion := "us-east-1"

	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "minio/minio:RELEASE.2025-04-22T22-12-26Z",
			ExposedPorts: []string{"9000/tcp"},
			Env: map[string]string{
				"MINIO_ROOT_USER":     "minioadmin",
				"MINIO_ROOT_PASSWORD": "minioadmin",
			},
			Cmd:        []string{"server", "/data"},
			WaitingFor: wait.ForHTTP("/minio/health/ready").WithPort("9000"),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := c.Terminate(ctx); err != nil {
			t.Log(err)
		}
	})

	mappedPort, err := c.MappedPort(ctx, "9000")
	require.NoError(t, err)

	hostIP, err := c.Host(ctx)
	require.NoError(t, err)

	awsEndpoint := "http://" + hostIP + ":" + mappedPort.Port()

	t.Setenv("AWS_REGION", awsRegion)
	t.Setenv("AWS_ENDPOINT_URL", awsEndpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "minioadmin")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "minioadmin")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	t.Setenv("AWS_PROFILE", "")

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(awsRegion),
		config.WithBaseEndpoint(awsEndpoint),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", "")),
	)
	require.NoError(t, err)

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = cfg.BaseEndpoint
	})

	bucketName := "test"
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &bucketName,
	})
	require.NoError(t, err)

	list, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err)

	require.Len(t, list.Buckets, 1)
	require.Equal(t, bucketName, *list.Buckets[0].Name)

	t.Setenv(bucketVar, bucketName)

	mux := http.NewServeMux()
	err = configureS3Handlers(mux)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, types.GetURLPath+"?id=test-file", nil)
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
