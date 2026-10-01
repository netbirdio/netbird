//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	fakeUpstreamImage = "nginx:alpine"
	fakeUpstreamAlias = "fakeupstream"
	fakeUpstreamPort  = "443/tcp"
)

// fakeUpstreamNginxConf serves a canned OpenAI-shaped chat completion for any
// path over a self-signed certificate, so the proxy reaches it only when the
// provider opts into skipping TLS verification.
const fakeUpstreamNginxConf = `pid /tmp/nginx.pid;
events {}
http {
  server {
    listen 443 ssl;
    ssl_certificate     /certs/tls.crt;
    ssl_certificate_key /certs/tls.key;
    location / {
      default_type application/json;
      return 200 '{"id":"chatcmpl-e2e","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}';
    }
  }
}
`

// FakeUpstream is a self-signed HTTPS server on the combined server's network,
// used to exercise provider skip_tls_verification: a proxy that verifies the
// certificate rejects it, one that skips verification reaches it.
type FakeUpstream struct {
	container testcontainers.Container
	workDir   string
	// URL is the upstream URL providers point at (https://<alias>).
	URL string
}

// StartFakeUpstream runs the self-signed upstream on the shared network.
func StartFakeUpstream(ctx context.Context, c *Combined) (*FakeUpstream, error) {
	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-upstream-*")
	if err != nil {
		return nil, fmt.Errorf("create upstream work dir: %w", err)
	}
	// Widen so the (non-root worker) nginx container can traverse the bind mount.
	if err := os.Chmod(workDir, 0o755); err != nil { //nolint:gosec // throwaway e2e cert dir
		return nil, fmt.Errorf("chmod upstream dir: %w", err)
	}
	if err := writeSelfSignedCert(workDir, []string{fakeUpstreamAlias}); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(workDir, "nginx.conf"), []byte(fakeUpstreamNginxConf), 0o644); err != nil { //nolint:gosec // non-secret e2e config
		return nil, fmt.Errorf("write nginx conf: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:          fakeUpstreamImage,
		ExposedPorts:   []string{fakeUpstreamPort},
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {fakeUpstreamAlias}},
		Cmd:            []string{"nginx", "-c", "/certs/nginx.conf", "-g", "daemon off;"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, workDir+":/certs:ro")
		},
		WaitingFor: wait.ForListeningPort(fakeUpstreamPort).WithStartupTimeout(60 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("start fake upstream container: %w", err)
	}

	return &FakeUpstream{container: ctr, workDir: workDir, URL: "https://" + fakeUpstreamAlias}, nil
}

// Logs returns the upstream container logs, for diagnostics on failure.
func (u *FakeUpstream) Logs(ctx context.Context) string {
	return containerLogs(ctx, u.container)
}

// Terminate stops the upstream container and cleans its work dir.
func (u *FakeUpstream) Terminate(ctx context.Context) error {
	var err error
	if u.container != nil {
		err = u.container.Terminate(ctx)
	}
	if u.workDir != "" {
		_ = os.RemoveAll(u.workDir)
	}
	return err
}
