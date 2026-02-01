//go:build darwin && !ios

package proxy

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const networksetupPath = "/usr/sbin/networksetup"

// Manager handles system-wide proxy configuration on macOS.
type Manager struct {
	mu               sync.Mutex
	stateManager     *statemanager.Manager
	modifiedServices []string
	enabled          bool
}

// NewManager creates a new proxy manager.
func NewManager(stateManager *statemanager.Manager) *Manager {
	return &Manager{
		stateManager: stateManager,
	}
}

// GetActiveNetworkServices returns the list of active network services.
func GetActiveNetworkServices() ([]string, error) {
	cmd := exec.Command(networksetupPath, "-listallnetworkservices")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	var services []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "asterisk") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

// EnableWebProxy enables web proxy for all active network services.
func (m *Manager) EnableWebProxy(host string, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled {
		log.Debug("web proxy already enabled")
		return nil
	}

	services, err := GetActiveNetworkServices()
	if err != nil {
		return err
	}

	var modifiedServices []string
	for _, service := range services {
		if err := m.enableProxyForService(service, host, port); err != nil {
			log.Warnf("enable proxy for %s: %v", service, err)
			continue
		}
		modifiedServices = append(modifiedServices, service)
	}

	m.modifiedServices = modifiedServices
	m.enabled = true
	m.updateState()

	log.Infof("enabled web proxy on %d services -> %s:%d", len(modifiedServices), host, port)
	return nil
}

func (m *Manager) enableProxyForService(service, host string, port int) error {
	portStr := fmt.Sprintf("%d", port)

	// Set web proxy (HTTP)
	cmd := exec.Command(networksetupPath, "-setwebproxy", service, host, portStr)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set web proxy: %w, output: %s", err, out)
	}

	// Enable web proxy
	cmd = exec.Command(networksetupPath, "-setwebproxystate", service, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable web proxy state: %w, output: %s", err, out)
	}

	// Set secure web proxy (HTTPS)
	cmd = exec.Command(networksetupPath, "-setsecurewebproxy", service, host, portStr)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set secure web proxy: %w, output: %s", err, out)
	}

	// Enable secure web proxy
	cmd = exec.Command(networksetupPath, "-setsecurewebproxystate", service, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable secure web proxy state: %w, output: %s", err, out)
	}

	log.Debugf("enabled proxy for service %s", service)
	return nil
}

// DisableWebProxy disables web proxy for all modified network services.
func (m *Manager) DisableWebProxy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		log.Debug("web proxy already disabled")
		return nil
	}

	services := m.modifiedServices
	if len(services) == 0 {
		services, _ = GetActiveNetworkServices()
	}

	for _, service := range services {
		if err := m.disableProxyForService(service); err != nil {
			log.Warnf("disable proxy for %s: %v", service, err)
		}
	}

	m.modifiedServices = nil
	m.enabled = false
	m.updateState()

	log.Info("disabled web proxy")
	return nil
}

func (m *Manager) disableProxyForService(service string) error {
	// Disable web proxy (HTTP)
	cmd := exec.Command(networksetupPath, "-setwebproxystate", service, "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("disable web proxy: %w, output: %s", err, out)
	}

	// Disable secure web proxy (HTTPS)
	cmd = exec.Command(networksetupPath, "-setsecurewebproxystate", service, "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("disable secure web proxy: %w, output: %s", err, out)
	}

	log.Debugf("disabled proxy for service %s", service)
	return nil
}

// SetAutoproxyURL sets the automatic proxy configuration URL (PAC file).
func (m *Manager) SetAutoproxyURL(pacURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	services, err := GetActiveNetworkServices()
	if err != nil {
		return err
	}

	var modifiedServices []string
	for _, service := range services {
		cmd := exec.Command(networksetupPath, "-setautoproxyurl", service, pacURL)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("set autoproxy for %s: %v, output: %s", service, err, out)
			continue
		}

		cmd = exec.Command(networksetupPath, "-setautoproxystate", service, "on")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("enable autoproxy for %s: %v, output: %s", service, err, out)
			continue
		}

		modifiedServices = append(modifiedServices, service)
		log.Debugf("set autoproxy URL for %s -> %s", service, pacURL)
	}

	m.modifiedServices = modifiedServices
	m.enabled = true
	m.updateState()

	return nil
}

// DisableAutoproxy disables automatic proxy configuration.
func (m *Manager) DisableAutoproxy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	services := m.modifiedServices
	if len(services) == 0 {
		services, _ = GetActiveNetworkServices()
	}

	for _, service := range services {
		cmd := exec.Command(networksetupPath, "-setautoproxystate", service, "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("disable autoproxy for %s: %v, output: %s", service, err, out)
		}
	}

	m.modifiedServices = nil
	m.enabled = false
	m.updateState()

	return nil
}

// IsEnabled returns whether the proxy is currently enabled.
func (m *Manager) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// Restore restores proxy settings from a previous state.
func (m *Manager) Restore(services []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, service := range services {
		if err := m.disableProxyForService(service); err != nil {
			log.Warnf("restore proxy for %s: %v", service, err)
		}
	}

	m.modifiedServices = nil
	m.enabled = false

	return nil
}

func (m *Manager) updateState() {
	if m.stateManager == nil {
		return
	}

	if m.enabled && len(m.modifiedServices) > 0 {
		state := &ShutdownState{
			ModifiedServices: m.modifiedServices,
		}
		if err := m.stateManager.UpdateState(state); err != nil {
			log.Errorf("update proxy state: %v", err)
		}
	} else {
		if err := m.stateManager.DeleteState(&ShutdownState{}); err != nil {
			log.Debugf("delete proxy state: %v", err)
		}
	}
}
