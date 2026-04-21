package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestParseFastPathFlag(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"one", "1", true},
		{"true lowercase", "true", true},
		{"true uppercase", "TRUE", true},
		{"true mixed case", "True", true},
		{"true with whitespace", "  true  ", true},
		{"zero", "0", false},
		{"false", "false", false},
		{"empty", "", false},
		{"yes", "yes", false},
		{"garbage", "garbage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseFastPathFlag(tt.value), "parseFastPathFlag(%q)", tt.value)
		})
	}
}

func TestFastPathFlag_EnabledDefaultsFalse(t *testing.T) {
	flag := &FastPathFlag{}
	assert.False(t, flag.Enabled(), "zero value flag should report disabled")
}

func TestFastPathFlag_NilSafeEnabled(t *testing.T) {
	var flag *FastPathFlag
	assert.False(t, flag.Enabled(), "nil flag should report disabled without panicking")
}

func TestFastPathFlag_SetEnabled(t *testing.T) {
	flag := &FastPathFlag{}
	flag.setEnabled(true)
	assert.True(t, flag.Enabled(), "flag should report enabled after setEnabled(true)")
	flag.setEnabled(false)
	assert.False(t, flag.Enabled(), "flag should report disabled after setEnabled(false)")
}

func TestFastPathRedisStore_InvalidURL(t *testing.T) {
	_, err := getFastPathRedisStore(context.Background(), "invalid-url")
	assert.Error(t, err, "Should fail with invalid URL")
}

func TestFastPathRedisStore_UnreachableHost(t *testing.T) {
	_, err := getFastPathRedisStore(context.Background(), "redis://127.0.0.1:59998")
	assert.Error(t, err, "Should fail when Redis is unreachable")
}

func TestRunFastPathFlagRoutine_DisabledWithoutEnvVar(t *testing.T) {
	t.Setenv(fastPathRedisURLEnv, "")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flag := RunFastPathFlagRoutine(ctx, 100*time.Millisecond, "any-key")
	require.NotNil(t, flag, "RunFastPathFlagRoutine should always return a non-nil flag")
	assert.False(t, flag.Enabled(), "flag should stay disabled when env var is unset")

	time.Sleep(250 * time.Millisecond)
	assert.False(t, flag.Enabled(), "flag should remain disabled even after wait when env var is unset")
}

func TestRunFastPathFlagRoutine_ReadsFlagFromRedis(t *testing.T) {
	redisURL, client := setupFastPathRedisContainer(t)

	t.Setenv(fastPathRedisURLEnv, redisURL)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flag := RunFastPathFlagRoutine(ctx, 100*time.Millisecond, "peerSyncFastPath")
	require.NotNil(t, flag)
	assert.False(t, flag.Enabled(), "flag should start disabled with no key")

	err := client.Set(ctx, "peerSyncFastPath", "1", 0).Err()
	require.NoError(t, err, "set redis key must succeed")

	assert.Eventually(t, flag.Enabled, 3*time.Second, 50*time.Millisecond, "flag should flip to enabled after Redis key is set to 1")

	err = client.Set(ctx, "peerSyncFastPath", "0", 0).Err()
	require.NoError(t, err, "reset redis key must succeed")

	assert.Eventually(t, func() bool {
		return !flag.Enabled()
	}, 3*time.Second, 50*time.Millisecond, "flag should flip back to disabled after Redis key is set to 0")

	err = client.Del(ctx, "peerSyncFastPath").Err()
	require.NoError(t, err, "delete redis key must succeed")

	err = client.Set(ctx, "peerSyncFastPath", "true", 0).Err()
	require.NoError(t, err)
	assert.Eventually(t, flag.Enabled, 3*time.Second, 50*time.Millisecond, "flag should accept \"true\" as enabled")
}

func TestRunFastPathFlagRoutine_MissingKeyKeepsDisabled(t *testing.T) {
	redisURL, _ := setupFastPathRedisContainer(t)
	t.Setenv(fastPathRedisURLEnv, redisURL)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flag := RunFastPathFlagRoutine(ctx, 100*time.Millisecond, "peerSyncFastPathAbsent")
	require.NotNil(t, flag)

	time.Sleep(400 * time.Millisecond)
	assert.False(t, flag.Enabled(), "flag should stay disabled when the key is missing in Redis")
}

func setupFastPathRedisContainer(t *testing.T) (string, *redis.Client) {
	t.Helper()

	ctx := context.Background()
	redisContainer, err := testcontainersredis.RunContainer(ctx,
		testcontainers.WithImage("redis:7"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("6379/tcp"),
		),
	)
	require.NoError(t, err, "create redis test container")

	t.Cleanup(func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate redis container: %s", err)
		}
	})

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	options, err := redis.ParseURL(redisURL)
	require.NoError(t, err)

	client := redis.NewClient(options)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("failed to close redis client: %s", err)
		}
	})

	return redisURL, client
}
