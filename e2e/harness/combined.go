//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/netbirdio/netbird/shared/management/client/rest"
)

const (
	combinedDockerfile = "combined/Dockerfile.multistage"
	combinedImageTag   = "netbird-e2e-combined:latest"
	combinedHTTPPort   = "8080/tcp"

	// containerInternalURL is how the server addresses itself: it listens on
	// :8080 inside the container, so the embedded IdP issuer and exposed
	// address both resolve there. Tests reach it via the mapped host port.
	containerInternalURL = "http://localhost:8080"
	containerIssuer      = containerInternalURL + "/oauth2"
)

// Combined is a running combined NetBird server (management + signal + relay +
// STUN + embedded IdP) plus the connection details tests need.
type Combined struct {
	container testcontainers.Container
	// BaseURL is the host-reachable management API root, e.g. http://127.0.0.1:51234.
	BaseURL string
	// PAT is the admin Personal Access Token minted via Bootstrap.
	PAT string

	api     *rest.Client
	workDir string
}

// StartCombined builds the combined server from its multistage Dockerfile and
// boots it with setup-PAT enabled, returning once the API is serving. The
// caller still owns minting the admin PAT via Bootstrap.
func StartCombined(ctx context.Context) (*Combined, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}

	// Build with the docker CLI (BuildKit) rather than testcontainers' classic
	// build path so the Dockerfile's cache mounts are honored and recompiles
	// stay incremental. testcontainers then just runs the tagged image.
	if err := buildCombinedImage(ctx, root); err != nil {
		return nil, err
	}

	// Work dir under /tmp so Docker Desktop file sharing (which excludes
	// macOS's /var/folders TMPDIR) can bind-mount it.
	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-combined-*")
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	cfg := fmt.Sprintf(combinedConfigYAML, containerInternalURL, containerIssuer)
	if err := os.WriteFile(filepath.Join(workDir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		return nil, fmt.Errorf("write combined config: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, "data"), 0o755); err != nil {
		return nil, fmt.Errorf("create datadir: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        combinedImageTag,
		ExposedPorts: []string{combinedHTTPPort},
		Env: map[string]string{
			"NB_SETUP_PAT_ENABLED": "true",
		},
		Cmd: []string{"--config", "/nb/config.yaml"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, workDir+":/nb")
		},
		WaitingFor: wait.ForHTTP("/api/instance").
			WithPort(combinedHTTPPort).
			WithStatusCodeMatcher(func(status int) bool { return status == 200 }).
			WithStartupTimeout(90 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start combined container: %w", err)
	}

	host, err := c.Host(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, fmt.Errorf("container host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, nat.Port(combinedHTTPPort))
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, fmt.Errorf("mapped port: %w", err)
	}

	return &Combined{
		container: c,
		BaseURL:   fmt.Sprintf("http://%s:%s", host, mapped.Port()),
		workDir:   workDir,
	}, nil
}

// buildCombinedImage builds the combined server image via the docker CLI with
// BuildKit enabled, so the Dockerfile's cache mounts work and unchanged sources
// reuse the layer + go caches. The image is tagged stably so reruns are cheap.
func buildCombinedImage(ctx context.Context, root string) error {
	cmd := exec.CommandContext(ctx, "docker", "build",
		"-f", combinedDockerfile,
		"-t", combinedImageTag,
		".",
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build combined image: %w\n%s", err, string(out))
	}
	return nil
}

// Terminate stops the container and removes the work dir.
func (c *Combined) Terminate(ctx context.Context) error {
	var err error
	if c.container != nil {
		err = c.container.Terminate(ctx)
	}
	if c.workDir != "" {
		_ = os.RemoveAll(c.workDir)
	}
	return err
}
