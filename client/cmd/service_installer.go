//go:build !ios && !android

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/util"
)

var ErrGetServiceStatus = fmt.Errorf("failed to get service status")

// Common service command setup
func setupServiceCommand(cmd *cobra.Command) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(serviceCmd)
	cmd.SetOut(cmd.OutOrStdout())
	return handleRebrand(cmd)
}

// Build service arguments for install/reconfigure
func buildServiceArguments() []string {
	args := []string{
		"service",
		"run",
		"--log-level",
		logLevel,
		"--daemon-addr",
		daemonAddr,
	}

	if managementURL != "" {
		args = append(args, "--management-url", managementURL)
	}

	if configPath != "" {
		args = append(args, "--config", configPath)
	}

	for _, logFile := range logFiles {
		args = append(args, "--log-file", logFile)
	}

	if profilesDisabled {
		args = append(args, "--disable-profiles")
	}

	if updateSettingsDisabled {
		args = append(args, "--disable-update-settings")
	}

	return args
}

// Configure platform-specific service settings
func configurePlatformSpecificSettings(svcConfig *service.Config) error {
	if runtime.GOOS == "linux" {
		// Respected only by systemd systems
		svcConfig.Dependencies = []string{"After=network.target syslog.target"}

		if logFile := util.FindFirstLogPath(logFiles); logFile != "" {
			setStdLogPath := true
			dir := filepath.Dir(logFile)

			if _, err := os.Stat(dir); err != nil {
				if err = os.MkdirAll(dir, 0750); err != nil {
					setStdLogPath = false
				}
			}

			if setStdLogPath {
				svcConfig.Option["LogOutput"] = true
				svcConfig.Option["LogDirectory"] = dir
			}
		}

		if err := configureSystemdNetworkd(); err != nil {
			log.Warnf("failed to configure systemd-networkd: %v", err)
		}
	}

	if runtime.GOOS == "windows" {
		svcConfig.Option["OnFailure"] = "restart"
	}

	return nil
}

// Create fully configured service config for install/reconfigure
func createServiceConfigForInstall() (*service.Config, error) {
	svcConfig, err := newSVCConfig()
	if err != nil {
		return nil, fmt.Errorf("create service config: %w", err)
	}

	svcConfig.Arguments = buildServiceArguments()
	if err = configurePlatformSpecificSettings(svcConfig); err != nil {
		return nil, fmt.Errorf("configure platform-specific settings: %w", err)
	}

	return svcConfig, nil
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install NetBird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setupServiceCommand(cmd); err != nil {
			return err
		}

		svcConfig, err := createServiceConfigForInstall()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		s, err := newSVC(newProgram(ctx, cancel), svcConfig)
		if err != nil {
			return err
		}

		if err := s.Install(); err != nil {
			return fmt.Errorf("install service: %w", err)
		}

		cmd.Println("NetBird service has been installed")
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstalls NetBird service from system",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setupServiceCommand(cmd); err != nil {
			return err
		}

		cfg, err := newSVCConfig()
		if err != nil {
			return fmt.Errorf("create service config: %w", err)
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		s, err := newSVC(newProgram(ctx, cancel), cfg)
		if err != nil {
			return err
		}

		if err := s.Uninstall(); err != nil {
			return fmt.Errorf("uninstall service: %w", err)
		}

		if runtime.GOOS == "linux" {
			if err := cleanupSystemdNetworkd(); err != nil {
				log.Warnf("failed to cleanup systemd-networkd configuration: %v", err)
			}
		}

		cmd.Println("NetBird service has been uninstalled")
		return nil
	},
}

var reconfigureCmd = &cobra.Command{
	Use:   "reconfigure",
	Short: "reconfigures NetBird service with new settings",
	Long: `Reconfigures the NetBird service with new settings without manual uninstall/install.
This command will temporarily stop the service, update its configuration, and restart it if it was running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setupServiceCommand(cmd); err != nil {
			return err
		}

		wasRunning, err := isServiceRunning()
		if err != nil && !errors.Is(err, ErrGetServiceStatus) {
			return fmt.Errorf("check service status: %w", err)
		}

		svcConfig, err := createServiceConfigForInstall()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		s, err := newSVC(newProgram(ctx, cancel), svcConfig)
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}

		if wasRunning {
			cmd.Println("Stopping NetBird service...")
			if err := s.Stop(); err != nil {
				cmd.Printf("Warning: failed to stop service: %v\n", err)
			}
		}

		cmd.Println("Removing existing service configuration...")
		if err := s.Uninstall(); err != nil {
			return fmt.Errorf("uninstall existing service: %w", err)
		}

		cmd.Println("Installing service with new configuration...")
		if err := s.Install(); err != nil {
			return fmt.Errorf("install service with new config: %w", err)
		}

		if wasRunning {
			cmd.Println("Starting NetBird service...")
			if err := s.Start(); err != nil {
				return fmt.Errorf("start service after reconfigure: %w", err)
			}
			cmd.Println("NetBird service has been reconfigured and started")
		} else {
			cmd.Println("NetBird service has been reconfigured")
		}

		return nil
	},
}

func isServiceRunning() (bool, error) {
	cfg, err := newSVCConfig()
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, err := newSVC(newProgram(ctx, cancel), cfg)
	if err != nil {
		return false, err
	}

	status, err := s.Status()
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrGetServiceStatus, err)
	}

	return status == service.StatusRunning, nil
}

const (
	networkdConf        = "/etc/systemd/networkd.conf"
	networkdConfDir     = "/etc/systemd/networkd.conf.d"
	networkdConfFile    = "/etc/systemd/networkd.conf.d/99-netbird.conf"
	networkdConfContent = `# Created by NetBird to prevent systemd-networkd from removing
# routes and policy rules managed by NetBird.

[Network]
ManageForeignRoutes=no
ManageForeignRoutingPolicyRules=no
`
)

// configureSystemdNetworkd creates a drop-in configuration file to prevent
// systemd-networkd from removing NetBird's routes and policy rules.
func configureSystemdNetworkd() error {
	if _, err := os.Stat(networkdConf); os.IsNotExist(err) {
		log.Debug("systemd-networkd not in use, skipping configuration")
		return nil
	}

	// nolint:gosec // standard networkd permissions
	if err := os.MkdirAll(networkdConfDir, 0755); err != nil {
		return fmt.Errorf("create networkd.conf.d directory: %w", err)
	}

	// nolint:gosec // standard networkd permissions
	if err := os.WriteFile(networkdConfFile, []byte(networkdConfContent), 0644); err != nil {
		return fmt.Errorf("write networkd configuration: %w", err)
	}

	return nil
}

// cleanupSystemdNetworkd removes the NetBird systemd-networkd configuration file.
func cleanupSystemdNetworkd() error {
	if _, err := os.Stat(networkdConfFile); os.IsNotExist(err) {
		return nil
	}

	if err := os.Remove(networkdConfFile); err != nil {
		return fmt.Errorf("remove networkd configuration: %w", err)
	}

	return nil
}
