//go:build !ios && !android

package cmd

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/server"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the NetBird daemon service",
}

var (
	serviceName    string
	serviceEnvVars []string
)

type program struct {
	ctx              context.Context
	cancel           context.CancelFunc
	serv             *grpc.Server
	serverInstance   *server.Server
	serverInstanceMu sync.Mutex
}

func init() {
	defaultServiceName := "netbird"
	if runtime.GOOS == "windows" {
		defaultServiceName = "Netbird"
	}

	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd, svcStatusCmd, installCmd, uninstallCmd, reconfigureCmd)
	serviceCmd.PersistentFlags().BoolVar(&profilesDisabled, "disable-profiles", false, "Disables profiles feature. If enabled, the client will not be able to change or edit any profile. To persist this setting, use: netbird service install --disable-profiles")
	serviceCmd.PersistentFlags().BoolVar(&updateSettingsDisabled, "disable-update-settings", false, "Disables update settings feature. If enabled, the client will not be able to change or edit any settings. To persist this setting, use: netbird service install --disable-update-settings")

	rootCmd.PersistentFlags().StringVarP(&serviceName, "service", "s", defaultServiceName, "Netbird system service name")
	serviceEnvDesc := `Sets extra environment variables for the service. ` +
		`You can specify a comma-separated list of KEY=VALUE pairs. ` +
		`E.g. --service-env NB_LOG_LEVEL=debug,CUSTOM_VAR=value`

	installCmd.Flags().StringSliceVar(&serviceEnvVars, "service-env", nil, serviceEnvDesc)
	reconfigureCmd.Flags().StringSliceVar(&serviceEnvVars, "service-env", nil, serviceEnvDesc)

	rootCmd.AddCommand(serviceCmd)
}

func newProgram(ctx context.Context, cancel context.CancelFunc) *program {
	ctx = internal.CtxInitState(ctx)
	return &program{ctx: ctx, cancel: cancel}
}

func newSVCConfig() (*service.Config, error) {
	config := &service.Config{
		Name:        serviceName,
		DisplayName: "Netbird",
		Description: "NetBird mesh network client",
		Option:      make(service.KeyValue),
		EnvVars:     make(map[string]string),
	}

	if len(serviceEnvVars) > 0 {
		extraEnvs, err := parseServiceEnvVars(serviceEnvVars)
		if err != nil {
			return nil, fmt.Errorf("parse service environment variables: %w", err)
		}
		config.EnvVars = extraEnvs
	}

	if runtime.GOOS == "linux" {
		config.EnvVars["SYSTEMD_UNIT"] = serviceName
	}

	return config, nil
}

func newSVC(prg *program, conf *service.Config) (service.Service, error) {
	return service.New(prg, conf)
}

func parseServiceEnvVars(envVars []string) (map[string]string, error) {
	envMap := make(map[string]string)

	for _, env := range envVars {
		if env == "" {
			continue
		}

		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid environment variable format: %s (expected KEY=VALUE)", env)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, fmt.Errorf("empty environment variable key in: %s", env)
		}

		envMap[key] = value
	}

	return envMap, nil
}
