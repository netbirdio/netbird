package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter/hook"
	"github.com/netbirdio/netbird/management/internals/server"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"
)

var newServer = func(config *nbconfig.Config, dnsDomain, mgmtSingleAccModeDomain string, mgmtPort int, mgmtMetricsPort int, disableMetrics, disableGeoliteUpdate, userDeleteFromIDPEnabled bool) server.Server {
	return server.NewServer(config, dnsDomain, mgmtSingleAccModeDomain, mgmtPort, mgmtMetricsPort, disableMetrics, disableGeoliteUpdate, userDeleteFromIDPEnabled)
}

func SetNewServer(fn func(config *nbconfig.Config, dnsDomain, mgmtSingleAccModeDomain string, mgmtPort int, mgmtMetricsPort int, disableMetrics, disableGeoliteUpdate, userDeleteFromIDPEnabled bool) server.Server) {
	newServer = fn
}

var (
	config *nbconfig.Config

	mgmtCmd = &cobra.Command{
		Use:   "management",
		Short: "start NetBird Management Server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			flag.Parse()

			//nolint
			ctx := context.WithValue(cmd.Context(), hook.ExecutionContextKey, hook.SystemSource)

			err := util.InitLog(logLevel, logFile)
			if err != nil {
				return fmt.Errorf("failed initializing log %v", err)
			}

			// detect whether user specified a port
			userPort := cmd.Flag("port").Changed

			config, err = loadMgmtConfig(ctx, nbconfig.MgmtConfigPath)
			if err != nil {
				return fmt.Errorf("failed reading provided config file: %s: %v", nbconfig.MgmtConfigPath, err)
			}

			if cmd.Flag(idpSignKeyRefreshEnabledFlagName).Changed {
				config.HttpConfig.IdpSignKeyRefreshEnabled = idpSignKeyRefreshEnabled
			}

			var tlsEnabled bool
			if mgmtLetsencryptDomain != "" || (config.HttpConfig.CertFile != "" && config.HttpConfig.CertKey != "") {
				tlsEnabled = true
			}

			if !userPort {
				// different defaults for port when tls enabled/disabled
				if tlsEnabled {
					mgmtPort = 443
				} else {
					mgmtPort = 80
				}
			}

			_, valid := dns.IsDomainName(dnsDomain)
			if !valid || len(dnsDomain) > 192 {
				return fmt.Errorf("failed parsing the provided dns-domain. Valid status: %t, Length: %d", valid, len(dnsDomain))
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			flag.Parse()

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			//nolint
			ctx = context.WithValue(ctx, hook.ExecutionContextKey, hook.SystemSource)

			err := handleRebrand(cmd)
			if err != nil {
				return fmt.Errorf("migrate files %v", err)
			}

			if _, err = os.Stat(config.Datadir); os.IsNotExist(err) {
				err = os.MkdirAll(config.Datadir, 0755)
				if err != nil {
					return fmt.Errorf("failed creating datadir: %s: %v", config.Datadir, err)
				}
			}

			if disableSingleAccMode {
				mgmtSingleAccModeDomain = ""
			}

			srv := newServer(config, dnsDomain, mgmtSingleAccModeDomain, mgmtPort, mgmtMetricsPort, disableMetrics, disableGeoliteUpdate, userDeleteFromIDPEnabled)
			go func() {
				if err := srv.Start(cmd.Context()); err != nil {
					log.Fatalf("Server error: %v", err)
				}
			}()

			stopChan := make(chan os.Signal, 1)
			signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
			select {
			case <-stopChan:
				log.Info("Received shutdown signal, stopping server...")
				err = srv.Stop()
				if err != nil {
					log.Errorf("Failed to stop server gracefully: %v", err)
				}
			case err := <-srv.Errors():
				log.Fatalf("Server stopped unexpectedly: %v", err)
			}

			return nil
		},
	}
)

func loadMgmtConfig(ctx context.Context, mgmtConfigPath string) (*nbconfig.Config, error) {
	loadedConfig := &nbconfig.Config{}
	if _, err := util.ReadJsonWithEnvSub(mgmtConfigPath, loadedConfig); err != nil {
		return nil, err
	}

	applyCommandLineOverrides(loadedConfig)

	// Apply EmbeddedIdP config to HttpConfig if embedded IdP is enabled
	err := applyEmbeddedIdPConfig(loadedConfig)
	if err != nil {
		return nil, err
	}

	if err := applyOIDCConfig(ctx, loadedConfig); err != nil {
		return nil, err
	}

	logConfigInfo(loadedConfig)

	if err := ensureEncryptionKey(ctx, mgmtConfigPath, loadedConfig); err != nil {
		return nil, err
	}

	return loadedConfig, nil
}

// applyCommandLineOverrides applies command-line flag overrides to the config
func applyCommandLineOverrides(cfg *nbconfig.Config) {
	if mgmtLetsencryptDomain != "" {
		cfg.HttpConfig.LetsEncryptDomain = mgmtLetsencryptDomain
	}
	if mgmtDataDir != "" {
		cfg.Datadir = mgmtDataDir
	}
	if certKey != "" && certFile != "" {
		cfg.HttpConfig.CertFile = certFile
		cfg.HttpConfig.CertKey = certKey
	}
}

// applyEmbeddedIdPConfig populates HttpConfig and EmbeddedIdP storage from config when embedded IdP is enabled.
// This allows users to only specify EmbeddedIdP config without duplicating values in HttpConfig.
func applyEmbeddedIdPConfig(cfg *nbconfig.Config) error {
	if cfg.EmbeddedIdP == nil || !cfg.EmbeddedIdP.Enabled {
		return nil
	}

	// apply some defaults based on the EmbeddedIdP config
	if disableSingleAccMode {
		// Embedded IdP requires single account mode - multiple account mode is not supported
		return fmt.Errorf("embedded IdP requires single account mode; multiple account mode is not supported with embedded IdP. Please remove --disable-single-account-mode flag")
	}
	// Enable user deletion from IDP by default if EmbeddedIdP is enabled
	userDeleteFromIDPEnabled = true

	// Set LocalAddress for embedded IdP if enabled, used for internal JWT validation
	cfg.EmbeddedIdP.LocalAddress = fmt.Sprintf("localhost:%d", mgmtPort)

	// Ensure HttpConfig exists
	if cfg.HttpConfig == nil {
		cfg.HttpConfig = &nbconfig.HttpServerConfig{}
	}

	// Set storage defaults based on Datadir
	if cfg.EmbeddedIdP.Storage.Type == "" {
		cfg.EmbeddedIdP.Storage.Type = "sqlite3"
	}
	if cfg.EmbeddedIdP.Storage.Config.File == "" && cfg.Datadir != "" {
		cfg.EmbeddedIdP.Storage.Config.File = path.Join(cfg.Datadir, "idp.db")
	}

	issuer := cfg.EmbeddedIdP.Issuer

	// Set AuthIssuer from EmbeddedIdP issuer
	if cfg.HttpConfig.AuthIssuer == "" {
		cfg.HttpConfig.AuthIssuer = issuer
	}

	// Set AuthAudience to the dashboard client ID
	if cfg.HttpConfig.AuthAudience == "" {
		cfg.HttpConfig.AuthAudience = "netbird-dashboard"
	}

	// Set CLIAuthAudience to the client app client ID
	if cfg.HttpConfig.CLIAuthAudience == "" {
		cfg.HttpConfig.CLIAuthAudience = "netbird-cli"
	}

	// Set AuthUserIDClaim to "sub" (standard OIDC claim)
	if cfg.HttpConfig.AuthUserIDClaim == "" {
		cfg.HttpConfig.AuthUserIDClaim = "sub"
	}

	// Set AuthKeysLocation to the JWKS endpoint
	if cfg.HttpConfig.AuthKeysLocation == "" {
		cfg.HttpConfig.AuthKeysLocation = issuer + "/keys"
	}

	// Set OIDCConfigEndpoint to the discovery endpoint
	if cfg.HttpConfig.OIDCConfigEndpoint == "" {
		cfg.HttpConfig.OIDCConfigEndpoint = issuer + "/.well-known/openid-configuration"
	}

	// Copy SignKeyRefreshEnabled from EmbeddedIdP config
	if cfg.EmbeddedIdP.SignKeyRefreshEnabled {
		cfg.HttpConfig.IdpSignKeyRefreshEnabled = true
	}

	return nil
}

// applyOIDCConfig fetches and applies OIDC configuration if endpoint is specified
func applyOIDCConfig(ctx context.Context, cfg *nbconfig.Config) error {
	oidcEndpoint := cfg.HttpConfig.OIDCConfigEndpoint
	if oidcEndpoint == "" || cfg.EmbeddedIdP != nil {
		return nil
	}

	log.WithContext(ctx).Infof("loading OIDC configuration from the provided IDP configuration endpoint %s", oidcEndpoint)
	oidcConfig, err := fetchOIDCConfig(ctx, oidcEndpoint)
	if err != nil {
		return err
	}
	log.WithContext(ctx).Infof("loaded OIDC configuration from the provided IDP configuration endpoint: %s", oidcEndpoint)

	log.WithContext(ctx).Infof("overriding HttpConfig.AuthIssuer with a new value %s, previously configured value: %s",
		oidcConfig.Issuer, cfg.HttpConfig.AuthIssuer)
	cfg.HttpConfig.AuthIssuer = oidcConfig.Issuer

	log.WithContext(ctx).Infof("overriding HttpConfig.AuthKeysLocation (JWT certs) with a new value %s, previously configured value: %s",
		oidcConfig.JwksURI, cfg.HttpConfig.AuthKeysLocation)
	cfg.HttpConfig.AuthKeysLocation = oidcConfig.JwksURI

	if err := applyDeviceAuthFlowConfig(ctx, cfg, &oidcConfig, oidcEndpoint); err != nil {
		return err
	}
	applyPKCEFlowConfig(ctx, cfg, &oidcConfig)

	return nil
}

// applyDeviceAuthFlowConfig applies OIDC config to DeviceAuthorizationFlow if enabled
func applyDeviceAuthFlowConfig(ctx context.Context, cfg *nbconfig.Config, oidcConfig *OIDCConfigResponse, oidcEndpoint string) error {
	if cfg.DeviceAuthorizationFlow == nil || strings.ToLower(cfg.DeviceAuthorizationFlow.Provider) == string(nbconfig.NONE) {
		return nil
	}

	log.WithContext(ctx).Infof("overriding DeviceAuthorizationFlow.TokenEndpoint with a new value: %s, previously configured value: %s",
		oidcConfig.TokenEndpoint, cfg.DeviceAuthorizationFlow.ProviderConfig.TokenEndpoint)
	cfg.DeviceAuthorizationFlow.ProviderConfig.TokenEndpoint = oidcConfig.TokenEndpoint

	log.WithContext(ctx).Infof("overriding DeviceAuthorizationFlow.DeviceAuthEndpoint with a new value: %s, previously configured value: %s",
		oidcConfig.DeviceAuthEndpoint, cfg.DeviceAuthorizationFlow.ProviderConfig.DeviceAuthEndpoint)
	cfg.DeviceAuthorizationFlow.ProviderConfig.DeviceAuthEndpoint = oidcConfig.DeviceAuthEndpoint

	u, err := url.Parse(oidcEndpoint)
	if err != nil {
		return err
	}
	log.WithContext(ctx).Infof("overriding DeviceAuthorizationFlow.ProviderConfig.Domain with a new value: %s, previously configured value: %s",
		u.Host, cfg.DeviceAuthorizationFlow.ProviderConfig.Domain)
	cfg.DeviceAuthorizationFlow.ProviderConfig.Domain = u.Host

	if cfg.DeviceAuthorizationFlow.ProviderConfig.Scope == "" {
		cfg.DeviceAuthorizationFlow.ProviderConfig.Scope = nbconfig.DefaultDeviceAuthFlowScope
	}
	return nil
}

// applyPKCEFlowConfig applies OIDC config to PKCEAuthorizationFlow if configured
func applyPKCEFlowConfig(ctx context.Context, cfg *nbconfig.Config, oidcConfig *OIDCConfigResponse) {
	if cfg.PKCEAuthorizationFlow == nil {
		return
	}
	log.WithContext(ctx).Infof("overriding PKCEAuthorizationFlow.TokenEndpoint with a new value: %s, previously configured value: %s",
		oidcConfig.TokenEndpoint, cfg.PKCEAuthorizationFlow.ProviderConfig.TokenEndpoint)
	cfg.PKCEAuthorizationFlow.ProviderConfig.TokenEndpoint = oidcConfig.TokenEndpoint

	log.WithContext(ctx).Infof("overriding PKCEAuthorizationFlow.AuthorizationEndpoint with a new value: %s, previously configured value: %s",
		oidcConfig.AuthorizationEndpoint, cfg.PKCEAuthorizationFlow.ProviderConfig.AuthorizationEndpoint)
	cfg.PKCEAuthorizationFlow.ProviderConfig.AuthorizationEndpoint = oidcConfig.AuthorizationEndpoint
}

// logConfigInfo logs informational messages about the loaded configuration
func logConfigInfo(cfg *nbconfig.Config) {
	if cfg.EmbeddedIdP != nil {
		log.Infof("running with the embedded IdP: %v", cfg.EmbeddedIdP.Issuer)
	}
	if cfg.Relay != nil {
		log.Infof("Relay addresses: %v", cfg.Relay.Addresses)
	}
}

// ensureEncryptionKey generates and saves a DataStoreEncryptionKey if not set
func ensureEncryptionKey(ctx context.Context, configPath string, cfg *nbconfig.Config) error {
	if cfg.DataStoreEncryptionKey != "" {
		return nil
	}

	log.WithContext(ctx).Infof("DataStoreEncryptionKey is not set, generating a new key")
	key, err := crypt.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate datastore encryption key: %v", err)
	}
	cfg.DataStoreEncryptionKey = key

	if err := util.DirectWriteJson(ctx, configPath, cfg); err != nil {
		return fmt.Errorf("failed to save config with new encryption key: %v", err)
	}
	log.WithContext(ctx).Infof("DataStoreEncryptionKey generated and saved to config")
	return nil
}

// OIDCConfigResponse used for parsing OIDC config response
type OIDCConfigResponse struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	DeviceAuthEndpoint    string `json:"device_authorization_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

// fetchOIDCConfig fetches OIDC configuration from the IDP
func fetchOIDCConfig(ctx context.Context, oidcEndpoint string) (OIDCConfigResponse, error) {
	res, err := http.Get(oidcEndpoint)
	if err != nil {
		return OIDCConfigResponse{}, fmt.Errorf("failed fetching OIDC configuration from endpoint %s %v", oidcEndpoint, err)
	}

	defer func() {
		err := res.Body.Close()
		if err != nil {
			log.WithContext(ctx).Debugf("failed closing response body %v", err)
		}
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return OIDCConfigResponse{}, fmt.Errorf("failed reading OIDC configuration response body: %v", err)
	}

	if res.StatusCode != 200 {
		return OIDCConfigResponse{}, fmt.Errorf("OIDC configuration request returned status %d with response: %s",
			res.StatusCode, string(body))
	}

	config := OIDCConfigResponse{}
	err = json.Unmarshal(body, &config)
	if err != nil {
		return OIDCConfigResponse{}, fmt.Errorf("failed unmarshaling OIDC configuration response: %v", err)
	}

	return config, nil
}

func handleRebrand(cmd *cobra.Command) error {
	var err error
	if logFile == defaultLogFile {
		if migrateToNetbird(oldDefaultLogFile, defaultLogFile) {
			cmd.Printf("will copy Log dir %s and its content to %s\n", oldDefaultLogDir, defaultLogDir)
			err = cpDir(oldDefaultLogDir, defaultLogDir)
			if err != nil {
				return err
			}
		}
	}
	if nbconfig.MgmtConfigPath == defaultMgmtConfig {
		if migrateToNetbird(oldDefaultMgmtConfig, defaultMgmtConfig) {
			cmd.Printf("will copy Config dir %s and its content to %s\n", oldDefaultMgmtConfigDir, defaultMgmtConfigDir)
			err = cpDir(oldDefaultMgmtConfigDir, defaultMgmtConfigDir)
			if err != nil {
				return err
			}
		}
	}
	if mgmtDataDir == defaultMgmtDataDir {
		if migrateToNetbird(oldDefaultMgmtDataDir, defaultMgmtDataDir) {
			cmd.Printf("will copy Config dir %s and its content to %s\n", oldDefaultMgmtDataDir, defaultMgmtDataDir)
			err = cpDir(oldDefaultMgmtDataDir, defaultMgmtDataDir)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func cpFile(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}

func copySymLink(source, dest string) error {
	link, err := os.Readlink(source)
	if err != nil {
		return err
	}
	return os.Symlink(link, dest)
}

func cpDir(src string, dst string) error {
	var err error
	var fds []os.DirEntry
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = os.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		fileInfo, err := os.Stat(srcfp)
		if err != nil {
			log.Fatalf("Couldn't get fileInfo; %v", err)
		}

		switch fileInfo.Mode() & os.ModeType {
		case os.ModeSymlink:
			if err = copySymLink(srcfp, dstfp); err != nil {
				log.Fatalf("Failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		case os.ModeDir:
			if err = cpDir(srcfp, dstfp); err != nil {
				log.Fatalf("Failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		default:
			if err = cpFile(srcfp, dstfp); err != nil {
				log.Fatalf("Failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		}
	}
	return nil
}

func migrateToNetbird(oldPath, newPath string) bool {
	_, errOld := os.Stat(oldPath)
	_, errNew := os.Stat(newPath)

	if errors.Is(errOld, fs.ErrNotExist) || errNew == nil {
		return false
	}

	return true
}
