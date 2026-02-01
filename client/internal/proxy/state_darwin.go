//go:build darwin && !ios

package proxy

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ShutdownState stores proxy state for cleanup on unclean shutdown.
type ShutdownState struct {
	ModifiedServices []string `json:"modified_services"`
}

// Name returns the state name for persistence.
func (s *ShutdownState) Name() string {
	return "proxy_state"
}

// Cleanup restores proxy settings after an unclean shutdown.
func (s *ShutdownState) Cleanup() error {
	if len(s.ModifiedServices) == 0 {
		return nil
	}

	log.Infof("cleaning up proxy state for %d services", len(s.ModifiedServices))

	for _, service := range s.ModifiedServices {
		// Disable web proxy (HTTP)
		cmd := exec.Command(networksetupPath, "-setwebproxystate", service, "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("cleanup web proxy for %s: %v, output: %s", service, err, out)
		}

		// Disable secure web proxy (HTTPS)
		cmd = exec.Command(networksetupPath, "-setsecurewebproxystate", service, "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("cleanup secure web proxy for %s: %v, output: %s", service, err, out)
		}

		// Disable autoproxy
		cmd = exec.Command(networksetupPath, "-setautoproxystate", service, "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warnf("cleanup autoproxy for %s: %v, output: %s", service, err, out)
		}

		log.Debugf("cleaned up proxy for service %s", service)
	}

	return nil
}

// RegisterState registers the proxy state with the state manager.
func RegisterState(stateManager *statemanager.Manager) {
	if stateManager == nil {
		return
	}
	stateManager.RegisterState(&ShutdownState{})
}

// GetProxyState returns the current proxy state from the command line.
func GetProxyState(service string) (webProxy, secureProxy, autoProxy bool, err error) {
	// Check web proxy state
	cmd := exec.Command(networksetupPath, "-getwebproxy", service)
	out, err := cmd.Output()
	if err != nil {
		return false, false, false, fmt.Errorf("get web proxy: %w", err)
	}
	webProxy = isProxyEnabled(string(out))

	// Check secure web proxy state
	cmd = exec.Command(networksetupPath, "-getsecurewebproxy", service)
	out, err = cmd.Output()
	if err != nil {
		return false, false, false, fmt.Errorf("get secure web proxy: %w", err)
	}
	secureProxy = isProxyEnabled(string(out))

	// Check autoproxy state
	cmd = exec.Command(networksetupPath, "-getautoproxyurl", service)
	out, err = cmd.Output()
	if err != nil {
		return false, false, false, fmt.Errorf("get autoproxy: %w", err)
	}
	autoProxy = isProxyEnabled(string(out))

	return webProxy, secureProxy, autoProxy, nil
}

func isProxyEnabled(output string) bool {
	return !contains(output, "Enabled: No") && contains(output, "Enabled: Yes")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
