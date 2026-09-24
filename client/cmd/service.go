//go:build !ios && !android

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"slices"
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

const defaultJSONSocket = "unix:///var/run/netbird-http.sock"

// forbiddenServiceEnvVars are the environment variables the service is never
// registered with, keyed in upper case since these are Windows names. Each one
// decides where the daemon resolves something it then uses with the privileges
// of the account it runs under — LocalSystem on Windows, root elsewhere: the
// executables it runs (PATH, PATHEXT, COMSPEC, SystemRoot, windir) or the
// directory it writes temporary files in (TEMP, TMP). The daemon needs none of
// them, and the utilities it shells out to are resolved by absolute path.
var forbiddenServiceEnvVars = map[string]struct{}{
	"PATH":       {},
	"PATHEXT":    {},
	"SYSTEMROOT": {},
	"WINDIR":     {},
	"COMSPEC":    {},
	"TEMP":       {},
	"TMP":        {},
}

// forbiddenServiceEnvPrefixes are the dynamic-loader families, refused whole
// rather than by name: LD_PRELOAD, DYLD_INSERT_LIBRARIES and their siblings all
// reach the loader of the process, the set differs per platform and libc, and
// new members arrive with new OS releases. Listing them one by one is a list
// that is wrong the moment it is written.
var forbiddenServiceEnvPrefixes = []string{"LD_", "DYLD_"}

var (
	serviceName      string
	serviceEnvVars   []string
	jsonSocket       string
	enableJSONSocket bool
)

type program struct {
	ctx      context.Context
	cancel   context.CancelFunc
	serv     *grpc.Server
	jsonServ *http.Server
	// jsonClient is the gateway's own connection to the daemon. It is held so
	// shutting the gateway down also closes it: nothing else references it once
	// the handlers are registered, so its transport goroutines would otherwise
	// outlive the server.
	jsonClient       *grpc.ClientConn
	jsonServMu       sync.Mutex
	serverInstance   *server.Server
	serverInstanceMu sync.Mutex
}

func init() {
	defaultServiceName := "netbird"
	if runtime.GOOS == "windows" {
		defaultServiceName = "Netbird"
	}

	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd, svcStatusCmd, installCmd, uninstallCmd, reconfigureCmd, resetParamsCmd)
	serviceCmd.PersistentFlags().BoolVar(&profilesDisabled, "disable-profiles", false, "Disables profiles feature. If enabled, the client will not be able to change or edit any profile. To persist this setting, use: netbird service install --disable-profiles")
	serviceCmd.PersistentFlags().BoolVar(&updateSettingsDisabled, "disable-update-settings", false, "Disables update settings feature. If enabled, the client will not be able to change or edit any settings. To persist this setting, use: netbird service install --disable-update-settings")
	serviceCmd.PersistentFlags().BoolVar(&captureEnabled, "enable-capture", false, "Enables packet capture via 'netbird debug capture'. To persist, use: netbird service install --enable-capture")
	serviceCmd.PersistentFlags().BoolVar(&networksDisabled, "disable-networks", false, "Disables network selection. If enabled, the client will not allow listing, selecting, or deselecting networks. To persist, use: netbird service install --disable-networks")
	serviceCmd.PersistentFlags().BoolVar(&enableJSONSocket, "enable-json-socket", false, "Enables the HTTP/JSON API socket served by grpc-gateway. To persist, use: netbird service install --enable-json-socket")
	serviceCmd.PersistentFlags().StringVar(&jsonSocket, "json-socket", defaultJSONSocket, "HTTP/JSON API socket address [unix|tcp]://[path|host:port]. Requires --enable-json-socket to serve. To persist, use: netbird service install --enable-json-socket --json-socket")

	rootCmd.PersistentFlags().StringVarP(&serviceName, "service", "s", defaultServiceName, "Netbird system service name")
	serviceEnvDesc := `Sets extra environment variables for the service. ` +
		`You can specify a comma-separated list of KEY=VALUE pairs. ` +
		`New keys are merged with previously saved env vars; existing keys are overwritten. ` +
		`Use --service-env "" to clear all saved env vars. ` +
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

		if isForbiddenServiceEnvVar(key) {
			return nil, fmt.Errorf("environment variable %s cannot be set on the service: it decides where the service resolves the executables, libraries or temporary files it uses", key)
		}

		envMap[key] = value
	}

	return envMap, nil
}

// isForbiddenServiceEnvVar reports whether name is one the service must not be
// registered with.
//
// The names are matched case-insensitively only on Windows, where they are the
// same variable however they are spelled. Elsewhere the environment is
// case-sensitive, so Path and PATH are two different variables and only the
// exact spelling is the one the loader reads.
func isForbiddenServiceEnvVar(name string) bool {
	if runtime.GOOS == "windows" {
		name = strings.ToUpper(name)
	}

	if _, forbidden := forbiddenServiceEnvVars[name]; forbidden {
		return true
	}

	return slices.ContainsFunc(forbiddenServiceEnvPrefixes, func(prefix string) bool {
		return strings.HasPrefix(name, prefix)
	})
}
