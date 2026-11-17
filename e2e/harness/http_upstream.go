//go:build e2e

package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	httpUpstreamImage   = "nginx:alpine"
	httpUpstreamAlias   = "httpupstream"
	httpUpstreamPort    = "8080/tcp"
	httpUpstreamLogPath = "/tmp/e2e-access.log"
)

// httpUpstreamNginxConf returns request details from a plain HTTP upstream and
// writes every request URI to an unbuffered file. Tests use unique path markers
// to distinguish requests that reached the upstream from proxy-generated
// responses with the same status.
const httpUpstreamNginxConf = `pid /tmp/nginx.pid;
worker_processes 1;
events {}
http {
  log_format e2e escape=json '{"uri":"$request_uri"}';
  access_log /tmp/e2e-access.log e2e;

  server {
    listen 8080;
    location / {
      default_type application/json;
      return 200 '{"source":"netbird-e2e-http-upstream","path":"$uri","request_uri":"$request_uri","configured_auth":"$http_x_e2e_proxy_key","authorization":"$http_authorization","cookie":"$http_cookie","netbird_user":"$http_x_netbird_user","netbird_groups":"$http_x_netbird_groups"}';
    }
  }
}
`

// HTTPUpstream is a plain HTTP server on the combined server's network. It
// reflects selected request properties and records request URIs for tests that
// need to distinguish proxy responses from upstream responses.
type HTTPUpstream struct {
	container     testcontainers.Container
	workDir       string
	directAddress string
	syncSequence  atomic.Uint64
	URL           string
}

// StartHTTPUpstream runs a request-observing nginx server on the shared network.
func StartHTTPUpstream(ctx context.Context, c *Combined) (*HTTPUpstream, error) {
	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-http-upstream-*")
	if err != nil {
		return nil, fmt.Errorf("create HTTP upstream work dir: %w", err)
	}
	if err := os.Chmod(workDir, 0o755); err != nil { //nolint:gosec // throwaway e2e config dir, must be traversable by the container uid
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("chmod HTTP upstream dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "nginx.conf"), []byte(httpUpstreamNginxConf), 0o644); err != nil { //nolint:gosec // non-secret e2e config
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("write HTTP upstream config: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:          httpUpstreamImage,
		ExposedPorts:   []string{httpUpstreamPort},
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {httpUpstreamAlias}},
		Cmd:            []string{"nginx", "-c", "/conf/nginx.conf", "-g", "daemon off;"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, workDir+":/conf:ro")
		},
		WaitingFor: wait.ForListeningPort(httpUpstreamPort).WithStartupTimeout(60 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		cleanupHTTPUpstreamStart(ctr, workDir)
		return nil, fmt.Errorf("start HTTP upstream container: %w", err)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		cleanupHTTPUpstreamStart(ctr, workDir)
		return nil, fmt.Errorf("HTTP upstream container host: %w", err)
	}
	mapped, err := ctr.MappedPort(ctx, nat.Port(httpUpstreamPort))
	if err != nil {
		cleanupHTTPUpstreamStart(ctr, workDir)
		return nil, fmt.Errorf("HTTP upstream mapped port: %w", err)
	}

	return &HTTPUpstream{
		container:     ctr,
		workDir:       workDir,
		directAddress: net.JoinHostPort(host, mapped.Port()),
		URL:           "http://" + httpUpstreamAlias + ":8080",
	}, nil
}

func cleanupHTTPUpstreamStart(ctr testcontainers.Container, workDir string) {
	if ctr != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = ctr.Terminate(cleanupCtx)
		cancel()
	}
	_ = os.RemoveAll(workDir)
}

// Synchronize waits until the upstream has finalized all requests received
// before a direct barrier request. The fixture runs one nginx worker and writes
// access logs without buffering, so observing the barrier in the file proves
// any earlier proxied request has also been recorded.
func (u *HTTPUpstream) Synchronize(ctx context.Context) error {
	marker := fmt.Sprintf("__e2e_upstream_barrier_%d__", u.syncSequence.Add(1))
	requestURL := (&url.URL{
		Scheme: "http",
		Host:   u.directAddress,
		Path:   "/" + marker,
	}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("create HTTP upstream barrier request: %w", err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send HTTP upstream barrier request: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read HTTP upstream barrier response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP upstream barrier returned status %d", resp.StatusCode)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		count, err := u.RequestCount(waitCtx, marker)
		if err != nil {
			return err
		}
		switch {
		case count == 1:
			return nil
		case count > 1:
			return fmt.Errorf("HTTP upstream recorded barrier %q %d times", marker, count)
		}

		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for HTTP upstream barrier: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

// RequestCount returns the number of recorded request URIs containing marker.
func (u *HTTPUpstream) RequestCount(ctx context.Context, marker string) (int, error) {
	if marker == "" {
		return 0, fmt.Errorf("request marker is empty")
	}

	reader, err := u.container.CopyFileFromContainer(ctx, httpUpstreamLogPath)
	if err != nil {
		return 0, fmt.Errorf("read HTTP upstream access log: %w", err)
	}
	defer reader.Close()

	count := 0
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var entry struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return 0, fmt.Errorf("decode HTTP upstream access log: %w", err)
		}
		if strings.Contains(entry.URI, marker) {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan HTTP upstream access log: %w", err)
	}
	return count, nil
}

// Logs returns the HTTP upstream container logs for failure diagnostics.
func (u *HTTPUpstream) Logs(ctx context.Context) string {
	return containerLogs(ctx, u.container)
}

// Terminate stops the HTTP upstream container and removes its work directory.
func (u *HTTPUpstream) Terminate(ctx context.Context) error {
	var err error
	if u.container != nil {
		err = u.container.Terminate(ctx)
	}
	if u.workDir != "" {
		_ = os.RemoveAll(u.workDir)
	}
	return err
}
