//go:build !ios && !android

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/configs"
	"github.com/netbirdio/netbird/util"
)

const serviceParamsFile = "service.json"

// serviceParams holds install-time service parameters that persist across
// uninstall/reinstall cycles. Saved to <stateDir>/service.json.
type serviceParams struct {
	LogLevel              string            `json:"log_level"`
	DaemonAddr            string            `json:"daemon_addr"`
	ManagementURL         string            `json:"management_url,omitempty"`
	ConfigPath            string            `json:"config_path,omitempty"`
	LogFiles              []string          `json:"log_files,omitempty"`
	DisableProfiles       bool              `json:"disable_profiles,omitempty"`
	DisableUpdateSettings bool              `json:"disable_update_settings,omitempty"`
	EnableCapture         bool              `json:"enable_capture,omitempty"`
	DisableNetworks       bool              `json:"disable_networks,omitempty"`
	ServiceEnvVars        map[string]string `json:"service_env_vars,omitempty"`
}

// serviceParamsPath returns the path to the service params file.
func serviceParamsPath() string {
	return filepath.Join(configs.StateDir, serviceParamsFile)
}

// loadServiceParams reads saved service parameters from disk.
// Returns nil with no error if the file does not exist.
func loadServiceParams() (*serviceParams, error) {
	path := serviceParamsPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil //nolint:nilnil
		}
		return nil, fmt.Errorf("read service params %s: %w", path, err)
	}

	var params serviceParams
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, fmt.Errorf("parse service params %s: %w", path, err)
	}

	return &params, nil
}

// saveServiceParams writes current service parameters to disk atomically
// with restricted permissions.
func saveServiceParams(params *serviceParams) error {
	path := serviceParamsPath()
	if err := util.WriteJsonWithRestrictedPermission(context.Background(), path, params); err != nil {
		return fmt.Errorf("save service params: %w", err)
	}
	return nil
}

// currentServiceParams captures the current state of all package-level
// variables into a serviceParams struct.
func currentServiceParams() *serviceParams {
	params := &serviceParams{
		LogLevel:              logLevel,
		DaemonAddr:            daemonAddr,
		ManagementURL:         managementURL,
		ConfigPath:            configPath,
		LogFiles:              logFiles,
		DisableProfiles:       profilesDisabled,
		DisableUpdateSettings: updateSettingsDisabled,
		EnableCapture:         captureEnabled,
		DisableNetworks:       networksDisabled,
	}

	if len(serviceEnvVars) > 0 {
		parsed, err := parseServiceEnvVars(serviceEnvVars)
		if err == nil {
			params.ServiceEnvVars = parsed
		}
	}

	return params
}

// loadAndApplyServiceParams loads saved params from disk and applies them
// to any flags that were not explicitly set.
func loadAndApplyServiceParams(cmd *cobra.Command) error {
	params, err := loadServiceParams()
	if err != nil {
		return err
	}
	applyServiceParams(cmd, params)
	return nil
}

// applyServiceParams merges saved parameters into package-level variables
// for any flag that was not explicitly set by the user (via CLI or env var).
// Flags that were Changed() are left untouched.
func applyServiceParams(cmd *cobra.Command, params *serviceParams) {
	if params == nil {
		return
	}

	// For fields with non-empty defaults (log-level, daemon-addr), keep the
	// != "" guard so that an older service.json missing the field doesn't
	// clobber the default with an empty string.
	if !rootCmd.PersistentFlags().Changed("log-level") && params.LogLevel != "" {
		logLevel = params.LogLevel
	}

	if !rootCmd.PersistentFlags().Changed("daemon-addr") && params.DaemonAddr != "" {
		daemonAddr = params.DaemonAddr
	}

	// For optional fields where empty means "use default", always apply so
	// that an explicit clear (--management-url "") persists across reinstalls.
	if !rootCmd.PersistentFlags().Changed("management-url") {
		managementURL = params.ManagementURL
	}

	if !rootCmd.PersistentFlags().Changed("config") {
		configPath = params.ConfigPath
	}

	if !rootCmd.PersistentFlags().Changed("log-file") {
		logFiles = params.LogFiles
	}

	if !serviceCmd.PersistentFlags().Changed("disable-profiles") {
		profilesDisabled = params.DisableProfiles
	}

	if !serviceCmd.PersistentFlags().Changed("disable-update-settings") {
		updateSettingsDisabled = params.DisableUpdateSettings
	}

	if !serviceCmd.PersistentFlags().Changed("enable-capture") {
		captureEnabled = params.EnableCapture
	}

	if !serviceCmd.PersistentFlags().Changed("disable-networks") {
		networksDisabled = params.DisableNetworks
	}

	applyServiceEnvParams(cmd, params)
}

// applyServiceEnvParams merges saved service environment variables.
// If --service-env was explicitly set with values, explicit values win on key
// conflict but saved keys not in the explicit set are carried over.
// If --service-env was explicitly set to empty, all saved env vars are cleared.
// If --service-env was not set, saved env vars are used entirely.
func applyServiceEnvParams(cmd *cobra.Command, params *serviceParams) {
	if !cmd.Flags().Changed("service-env") {
		if len(params.ServiceEnvVars) > 0 {
			// No explicit env vars: rebuild serviceEnvVars from saved params.
			serviceEnvVars = envMapToSlice(params.ServiceEnvVars)
		}
		return
	}

	// Flag was explicitly set: parse what the user provided.
	explicit, err := parseServiceEnvVars(serviceEnvVars)
	if err != nil {
		cmd.PrintErrf("Warning: parse explicit service env vars for merge: %v\n", err)
		return
	}

	// If the user passed an empty value (e.g. --service-env ""), clear all
	// saved env vars rather than merging.
	if len(explicit) == 0 {
		serviceEnvVars = nil
		return
	}

	if len(params.ServiceEnvVars) == 0 {
		return
	}

	// Merge saved values underneath explicit ones.
	merged := make(map[string]string, len(params.ServiceEnvVars)+len(explicit))
	maps.Copy(merged, params.ServiceEnvVars)
	maps.Copy(merged, explicit) // explicit wins on conflict
	serviceEnvVars = envMapToSlice(merged)
}

var resetParamsCmd = &cobra.Command{
	Use:   "reset-params",
	Short: "Remove saved service install parameters",
	Long:  "Removes the saved service.json file so the next install uses default parameters.",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := serviceParamsPath()
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				cmd.Println("No saved service parameters found")
				return nil
			}
			return fmt.Errorf("remove service params: %w", err)
		}
		cmd.Printf("Removed saved service parameters (%s)\n", path)
		return nil
	},
}

// envMapToSlice converts a map of env vars to a KEY=VALUE slice.
func envMapToSlice(m map[string]string) []string {
	s := make([]string, 0, len(m))
	for k, v := range m {
		s = append(s, k+"="+v)
	}
	return s
}
