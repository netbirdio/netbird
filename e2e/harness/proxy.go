//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	proxyDockerfile = "proxy/Dockerfile.multistage"
	// defaultProxyImage is the published reverse-proxy release used by default.
	// Override with NB_E2E_PROXY_IMAGE; a value without a "/" is built locally.
	defaultProxyImage = "netbirdio/reverse-proxy:0.74.0-rc.2"
	proxyAlias        = "proxy"

	// AgentNetworkCluster is the proxy cluster the e2e provider bootstraps and
	// the proxy serves. It must equal the management's exposed domain
	// (combinedAlias) — the working manual setup uses one NETBIRD_DOMAIN for
	// both. The agent-network endpoint is <subdomain>.<cluster>.
	AgentNetworkCluster = combinedAlias
)

// Proxy is a running agent-network gateway (netbird proxy) container.
type Proxy struct {
	container testcontainers.Container
	workDir   string
}

// StartProxy builds the proxy image and runs it on the combined server's
// network, registered via the given account proxy token and serving the
// AgentNetworkCluster over a self-signed wildcard cert. It does not wait for
// peer connectivity — callers poll management for the proxy peer.
func StartProxy(ctx context.Context, c *Combined, proxyToken string) (*Proxy, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	proxyImage, err := resolveImage(ctx, root, "NB_E2E_PROXY_IMAGE", defaultProxyImage, proxyDockerfile)
	if err != nil {
		return nil, err
	}

	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-proxy-*")
	if err != nil {
		return nil, fmt.Errorf("create proxy work dir: %w", err)
	}
	if err := writeSelfSignedCert(workDir, []string{"*." + AgentNetworkCluster, AgentNetworkCluster}); err != nil {
		return nil, err
	}

	req := testcontainers.ContainerRequest{
		Image:          proxyImage,
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {proxyAlias}},
		Env: map[string]string{
			"NB_PROXY_TOKEN":                 proxyToken,
			"NB_PROXY_MANAGEMENT_ADDRESS":    combinedExposedURL,
			"NB_PROXY_DOMAIN":                AgentNetworkCluster,
			"NB_PROXY_ADDRESS":               ":443",
			"NB_PROXY_CERTIFICATE_DIRECTORY": "/certs",
			"NB_PROXY_HEALTH_ADDRESS":        ":8081",
			"NB_PROXY_LOG_LEVEL":             "debug",
			"NB_PROXY_PRIVATE":               "true",
			// Management is plain HTTP in-cluster, so allow the proxy token to
			// ride a non-TLS gRPC connection.
			"NB_PROXY_ALLOW_INSECURE": "true",
			// The combined server multiplexes the relay over WebSocket on :8080
			// (no QUIC listener). The proxy's embedded relay client defaults to
			// QUIC, which fails here and flaps the relay link, churning the
			// proxy peer so it never stably registers. Force WS transport.
			"NB_RELAY_TRANSPORT": "ws",
			// Trace the embedded client (relay / signal / handshake) so
			// peer-registration issues are visible in the proxy logs.
			"NB_PROXY_CLIENT_LOG_LEVEL": "trace",
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, workDir+":/certs")
			hc.CapAdd = append(hc.CapAdd, "NET_ADMIN", "SYS_ADMIN", "SYS_RESOURCE", "NET_BIND_SERVICE")
		},
		WaitingFor: wait.ForLog("Initial mapping sync complete").WithStartupTimeout(90 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start proxy container: %w", err)
	}

	return &Proxy{container: ctr, workDir: workDir}, nil
}

// Logs returns the proxy container logs, for diagnostics on failure.
func (p *Proxy) Logs(ctx context.Context) string {
	return containerLogs(ctx, p.container)
}

// Terminate stops the proxy container and cleans its work dir.
func (p *Proxy) Terminate(ctx context.Context) error {
	var err error
	if p.container != nil {
		err = p.container.Terminate(ctx)
	}
	if p.workDir != "" {
		_ = os.RemoveAll(p.workDir)
	}
	return err
}
