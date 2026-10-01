//go:build e2e

package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	proxyDockerfile = "proxy/Dockerfile.multistage"
	// defaultProxyImage is the local tag the reverse proxy is built under from
	// proxyDockerfile. Override with NB_E2E_PROXY_IMAGE: a value with a "/" is
	// pulled as a published image; a bare tag is built under that name.
	defaultProxyImage = "netbird-reverse-proxy:e2e"
	proxyAlias        = "proxy"
	proxyHTTPSPort    = "443/tcp"

	// AgentNetworkCluster is the proxy cluster the e2e provider bootstraps and
	// the proxy serves. It must equal the management's exposed domain
	// (combinedAlias) — the working manual setup uses one NETBIRD_DOMAIN for
	// both. The agent-network endpoint is <subdomain>.<cluster>.
	AgentNetworkCluster = combinedAlias
)

// Proxy is a running agent-network gateway (netbird proxy) container.
type Proxy struct {
	container    testcontainers.Container
	workDir      string
	httpsAddress string
}

// StartProxy builds the proxy image and runs it on the combined server's
// network, registered via the given account proxy token and serving the
// AgentNetworkCluster over a self-signed wildcard cert. It does not wait for
// peer connectivity — callers poll management for the proxy peer.
// StartProxy launches the reverse-proxy container. Optional envOverrides are
// merged into the container environment after the defaults, so callers can set
// or override any NB_PROXY_* var (e.g. NB_PROXY_TUNNEL_CACHE_TTL for tests that
// need a short authorization-cache window).
func StartProxy(ctx context.Context, c *Combined, proxyToken string, envOverrides ...map[string]string) (*Proxy, error) {
	root, err := repoRoot(ctx)
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
	// MkdirTemp creates the dir 0700; widen it so the non-root proxy container
	// can traverse the bind-mounted cert dir on Linux CI runners.
	if err := os.Chmod(workDir, 0o755); err != nil { //nolint:gosec // throwaway e2e cert dir, must be traversable by the proxy container uid
		return nil, fmt.Errorf("chmod proxy cert dir: %w", err)
	}
	if err := writeSelfSignedCert(workDir, []string{"*." + AgentNetworkCluster, AgentNetworkCluster}); err != nil {
		return nil, err
	}

	req := testcontainers.ContainerRequest{
		Image:          proxyImage,
		ExposedPorts:   []string{proxyHTTPSPort},
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

	for _, ov := range envOverrides {
		for k, v := range ov {
			req.Env[k] = v
		}
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("start proxy container: %w", err)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		_ = ctr.Terminate(ctx)
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("proxy container host: %w", err)
	}
	mapped, err := ctr.MappedPort(ctx, nat.Port(proxyHTTPSPort))
	if err != nil {
		_ = ctr.Terminate(ctx)
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("proxy mapped HTTPS port: %w", err)
	}

	return &Proxy{
		container:    ctr,
		workDir:      workDir,
		httpsAddress: net.JoinHostPort(host, mapped.Port()),
	}, nil
}

// HTTPSGet reaches a public service through the proxy's host-mapped HTTPS
// listener while retaining domain as the request Host and TLS server name.
// Connections are not reused so callers can observe mapping removal without
// an existing connection outliving the route.
func (p *Proxy) HTTPSGet(ctx context.Context, domain, path string, headers http.Header) (int, string, error) {
	requestURL := &url.URL{Scheme: "https", Host: domain, Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return 0, "", fmt.Errorf("create proxy request: %w", err)
	}
	req.Header = headers.Clone()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", p.httpsAddress)
		},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // the e2e proxy intentionally uses a generated self-signed certificate
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request public proxy service: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("read public proxy response: %w", err)
	}
	return resp.StatusCode, string(body), nil
}

// ProxyDebugClient is one per-account embedded client the proxy runs, as the
// proxy's debug endpoint reports it.
type ProxyDebugClient struct {
	AccountID    string   `json:"account_id"`
	ServiceCount int      `json:"service_count"`
	ServiceKeys  []string `json:"service_keys"`
}

// DebugClients lists the per-account clients the proxy is running, through
// the proxy's own debug CLI inside the container. The proxy must be started
// with NB_PROXY_DEBUG_ENDPOINT=true.
func (p *Proxy) DebugClients(ctx context.Context) ([]ProxyDebugClient, error) {
	code, reader, err := p.container.Exec(ctx,
		[]string{"/usr/bin/netbird-proxy", "debug", "clients", "--json"}, tcexec.Multiplexed())
	if err != nil {
		return nil, fmt.Errorf("exec debug clients: %w", err)
	}
	out, _ := io.ReadAll(reader)
	if code != 0 {
		return nil, fmt.Errorf("debug clients exited %d: %s", code, string(out))
	}
	// stderr is multiplexed in; the JSON document starts at the first brace.
	start := bytes.IndexByte(out, '{')
	if start < 0 {
		return nil, fmt.Errorf("no JSON in debug clients output: %s", string(out))
	}
	var resp struct {
		Clients []ProxyDebugClient `json:"clients"`
	}
	if err := json.NewDecoder(bytes.NewReader(out[start:])).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode debug clients output: %w", err)
	}
	return resp.Clients, nil
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
