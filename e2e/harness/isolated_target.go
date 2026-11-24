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
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const isolatedTargetPort = "8080"

// isolatedTargetNginxConf answers every request with the address it came from, so a
// test can tell which peer forwarded the request.
const isolatedTargetNginxConf = `pid /tmp/nginx.pid;
worker_processes 1;
events {}
http {
  access_log off;
  server {
    listen ` + isolatedTargetPort + `;
    location / {
      default_type text/plain;
      return 200 '$remote_addr';
    }
  }
}
`

// IsolatedTarget is an HTTP server alone on an internal Docker network. Docker does
// not route between networks, and an internal one has no route out, so only
// containers attached to its network reach it: any other peer reaches it only
// through a peer that is attached and routes for it, such as an exit node.
type IsolatedTarget struct {
	container testcontainers.Container
	network   *testcontainers.DockerNetwork
	workDir   string
	// IP is the target's address on its network.
	IP string
}

// StartIsolatedTarget creates the internal network and runs the target on it.
func StartIsolatedTarget(ctx context.Context) (*IsolatedTarget, error) {
	net, err := network.New(ctx, network.WithInternal())
	if err != nil {
		return nil, fmt.Errorf("create isolated network: %w", err)
	}
	target := &IsolatedTarget{network: net}

	if err := target.start(ctx); err != nil {
		_ = target.Terminate(context.Background())
		return nil, err
	}
	return target, nil
}

func (t *IsolatedTarget) start(ctx context.Context) error {
	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-isolated-target-*")
	if err != nil {
		return fmt.Errorf("create isolated target work dir: %w", err)
	}
	t.workDir = workDir
	if err := os.Chmod(workDir, 0o755); err != nil { //nolint:gosec // throwaway e2e config dir, must be traversable by the container uid
		return fmt.Errorf("chmod isolated target dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "nginx.conf"), []byte(isolatedTargetNginxConf), 0o644); err != nil { //nolint:gosec // non-secret e2e config
		return fmt.Errorf("write isolated target config: %w", err)
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:    httpUpstreamImage,
			Networks: []string{t.network.Name},
			Cmd:      []string{"nginx", "-c", "/conf/nginx.conf", "-g", "daemon off;"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds, workDir+":/conf:ro")
			},
			// The internal network publishes no ports to the host, so readiness is
			// checked from inside the container.
			WaitingFor: wait.ForExec([]string{"wget", "-q", "-O", "/dev/null", "http://127.0.0.1:" + isolatedTargetPort + "/"}).
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	t.container = ctr
	if err != nil {
		return fmt.Errorf("start isolated target container: %w", err)
	}

	ip, err := containerNetworkIP(ctx, ctr, t.network.Name)
	if err != nil {
		return err
	}
	t.IP = ip
	return nil
}

// NetworkName returns the internal network the target is on, for attaching the
// peer that routes to it.
func (t *IsolatedTarget) NetworkName() string {
	return t.network.Name
}

// URL returns the target's address for requests from inside the overlay.
func (t *IsolatedTarget) URL() string {
	return "http://" + t.IP + ":" + isolatedTargetPort + "/"
}

// Logs returns the target container logs for failure diagnostics.
func (t *IsolatedTarget) Logs(ctx context.Context) string {
	return containerLogs(ctx, t.container)
}

// Terminate stops the target and removes its network and work dir.
func (t *IsolatedTarget) Terminate(ctx context.Context) error {
	var err error
	if t.container != nil {
		err = t.container.Terminate(ctx)
	}
	if t.network != nil {
		_ = t.network.Remove(ctx)
	}
	if t.workDir != "" {
		_ = os.RemoveAll(t.workDir)
	}
	return err
}

// containerNetworkIP returns a container's address on the named network.
func containerNetworkIP(ctx context.Context, ctr testcontainers.Container, networkName string) (string, error) {
	info, err := ctr.Inspect(ctx)
	if err != nil {
		return "", fmt.Errorf("inspect container: %w", err)
	}
	if info.NetworkSettings == nil || info.NetworkSettings.Networks[networkName] == nil {
		return "", fmt.Errorf("container is not attached to network %s", networkName)
	}
	ip := info.NetworkSettings.Networks[networkName].IPAddress
	if ip == "" {
		return "", fmt.Errorf("container has no address on network %s", networkName)
	}
	return ip, nil
}
