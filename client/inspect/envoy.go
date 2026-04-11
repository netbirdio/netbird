package inspect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	envoyStartTimeout   = 15 * time.Second
	envoyHealthInterval = 500 * time.Millisecond
	envoyStopTimeout    = 10 * time.Second
	envoyDrainTime      = 5
)

// envoyManager manages the lifecycle of an envoy sidecar process.
type envoyManager struct {
	log        *log.Entry
	cmd        *exec.Cmd
	configPath string
	listenPort uint16
	adminPort  uint16
	cancel     context.CancelFunc

	blockPagePath string

	mu      sync.Mutex
	running bool
}

// startEnvoy finds the envoy binary, generates config, and spawns the process.
// It blocks until envoy reports healthy or the timeout expires.
func startEnvoy(ctx context.Context, logger *log.Entry, config Config) (*envoyManager, error) {
	envCfg := config.Envoy
	if envCfg == nil {
		return nil, fmt.Errorf("envoy config is nil")
	}

	binaryPath, err := findEnvoyBinary(envCfg.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("find envoy binary: %w", err)
	}

	// Pick admin port
	adminPort := envCfg.AdminPort
	if adminPort == 0 {
		p, err := findFreePort()
		if err != nil {
			return nil, fmt.Errorf("find free admin port: %w", err)
		}
		adminPort = p
	}

	// Pick listener port
	listenPort, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("find free listener port: %w", err)
	}

	// Use a private temp directory (0700) to prevent local attackers from
	// replacing the config file between write and envoy read.
	configDir, err := os.MkdirTemp("", "nb-envoy-*")
	if err != nil {
		return nil, fmt.Errorf("create envoy config directory: %w", err)
	}

	// Write the block page HTML for envoy's direct_response to reference.
	blockPagePath := filepath.Join(configDir, "block.html")
	blockHTML := fmt.Sprintf(blockPageHTML, "blocked domain", "this domain")
	if err := os.WriteFile(blockPagePath, []byte(blockHTML), 0600); err != nil {
		return nil, fmt.Errorf("write envoy block page: %w", err)
	}

	// Generate config with the block page path embedded.
	bootstrap, err := generateBootstrap(config, listenPort, adminPort, blockPagePath)
	if err != nil {
		return nil, fmt.Errorf("generate envoy bootstrap: %w", err)
	}

	configPath := filepath.Join(configDir, "bootstrap.yaml")
	if err := os.WriteFile(configPath, bootstrap, 0600); err != nil {
		return nil, fmt.Errorf("write envoy config: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(ctx, binaryPath,
		"-c", configPath,
		"--drain-time-s", fmt.Sprintf("%d", envoyDrainTime),
	)

	// Pipe envoy output to our logger.
	cmd.Stdout = &logWriter{entry: logger, level: log.DebugLevel}
	cmd.Stderr = &logWriter{entry: logger, level: log.WarnLevel}

	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(configPath)
		return nil, fmt.Errorf("start envoy: %w", err)
	}

	mgr := &envoyManager{
		log:           logger,
		cmd:           cmd,
		configPath:    configPath,
		listenPort:    listenPort,
		adminPort:     adminPort,
		blockPagePath: blockPagePath,
		cancel:        cancel,
		running:       true,
	}

	// Wait for envoy to become healthy.
	if err := mgr.waitHealthy(ctx); err != nil {
		mgr.Stop()
		return nil, fmt.Errorf("wait for envoy readiness: %w", err)
	}

	logger.Infof("inspect: envoy started (pid=%d, listen=%d, admin=%d)", cmd.Process.Pid, listenPort, adminPort)

	// Monitor process exit in background.
	go mgr.monitor()

	return mgr, nil
}

// ListenAddr returns the address envoy listens on for forwarded connections.
func (m *envoyManager) ListenAddr() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), m.listenPort)
}

// AdminAddr returns the envoy admin API address.
func (m *envoyManager) AdminAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.adminPort)
}

// Reload writes a new config and sends SIGHUP to envoy.
func (m *envoyManager) Reload(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return fmt.Errorf("envoy is not running")
	}

	bootstrap, err := generateBootstrap(config, m.listenPort, m.adminPort, m.blockPagePath)
	if err != nil {
		return fmt.Errorf("generate envoy bootstrap: %w", err)
	}

	if err := os.WriteFile(m.configPath, bootstrap, 0600); err != nil {
		return fmt.Errorf("write envoy config: %w", err)
	}

	if err := signalReload(m.cmd.Process); err != nil {
		return fmt.Errorf("signal envoy reload: %w", err)
	}

	m.log.Debugf("inspect: envoy config reloaded")
	return nil
}

// Healthy checks the envoy admin API /ready endpoint.
func (m *envoyManager) Healthy() bool {
	resp, err := http.Get(fmt.Sprintf("http://%s/ready", m.AdminAddr()))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Stop terminates the envoy process and cleans up.
func (m *envoyManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}
	m.running = false

	m.cancel()

	if m.cmd.Process != nil {
		done := make(chan struct{})
		go func() {
			m.cmd.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(envoyStopTimeout):
			m.log.Warnf("inspect: envoy did not exit in %s, killing", envoyStopTimeout)
			m.cmd.Process.Kill()
			<-done
		}
	}

	os.RemoveAll(filepath.Dir(m.configPath))
	m.log.Infof("inspect: envoy stopped")
}

// waitHealthy polls the admin API until envoy is ready or timeout.
func (m *envoyManager) waitHealthy(ctx context.Context) error {
	deadline := time.After(envoyStartTimeout)
	ticker := time.NewTicker(envoyHealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("envoy not ready after %s", envoyStartTimeout)
		case <-ticker.C:
			if m.Healthy() {
				return nil
			}
		}
	}
}

// monitor watches for unexpected envoy exits.
func (m *envoyManager) monitor() {
	err := m.cmd.Wait()

	m.mu.Lock()
	wasRunning := m.running
	m.running = false
	m.mu.Unlock()

	if wasRunning {
		m.log.Errorf("inspect: envoy exited unexpectedly: %v", err)
	}
}

// findEnvoyBinary resolves the envoy binary path.
func findEnvoyBinary(configPath string) (string, error) {
	if configPath != "" {
		if _, err := os.Stat(configPath); err != nil {
			return "", fmt.Errorf("envoy binary not found at %s: %w", configPath, err)
		}
		return configPath, nil
	}

	path, err := exec.LookPath("envoy")
	if err != nil {
		return "", fmt.Errorf("envoy not found in PATH: %w", err)
	}
	return path, nil
}

// findFreePort asks the OS for an available TCP port.
func findFreePort() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return port, nil
}

// logWriter adapts log.Entry to io.Writer for piping process output.
type logWriter struct {
	entry *log.Entry
	level log.Level
}

func (w *logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n\r")
	if msg == "" {
		return len(p), nil
	}
	switch w.level {
	case log.WarnLevel:
		w.entry.Warn(msg)
	default:
		w.entry.Debug(msg)
	}
	return len(p), nil
}

// Ensure logWriter satisfies io.Writer.
var _ io.Writer = (*logWriter)(nil)
