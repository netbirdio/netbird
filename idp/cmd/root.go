package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/idp/oidcprovider"
	"github.com/netbirdio/netbird/util"
)

// Config holds the IdP server configuration
type Config struct {
	ListenPort            int
	Issuer                string
	DataDir               string
	LogLevel              string
	LogFile               string
	DevMode               bool
	DashboardRedirectURIs []string
	CLIRedirectURIs       []string
	DashboardClientID     string
	CLIClientID           string
}

var (
	config  *Config
	rootCmd = &cobra.Command{
		Use:           "idp",
		Short:         "NetBird Identity Provider",
		Long:          "Embedded OIDC Identity Provider for NetBird",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          execute,
	}
)

func init() {
	_ = util.InitLog("trace", util.LogConsole)
	config = &Config{}

	rootCmd.PersistentFlags().IntVarP(&config.ListenPort, "port", "p", 33081, "port to listen on")
	rootCmd.PersistentFlags().StringVarP(&config.Issuer, "issuer", "i", "", "OIDC issuer URL (default: http://localhost:<port>)")
	rootCmd.PersistentFlags().StringVarP(&config.DataDir, "data-dir", "d", "/var/lib/netbird", "directory to store IdP data")
	rootCmd.PersistentFlags().StringVar(&config.LogLevel, "log-level", "info", "log level (trace, debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&config.LogFile, "log-file", "console", "log file path or 'console'")
	rootCmd.PersistentFlags().BoolVar(&config.DevMode, "dev-mode", false, "enable development mode (allows HTTP)")
	rootCmd.PersistentFlags().StringSliceVar(&config.DashboardRedirectURIs, "dashboard-redirect-uris", []string{
		"http://localhost:3000/callback",
		"http://localhost:3000/silent-callback",
	}, "allowed redirect URIs for dashboard client")
	rootCmd.PersistentFlags().StringSliceVar(&config.CLIRedirectURIs, "cli-redirect-uris", []string{
		"http://localhost:53000",
		"http://localhost:54000",
	}, "allowed redirect URIs for CLI client")
	rootCmd.PersistentFlags().StringVar(&config.DashboardClientID, "dashboard-client-id", "netbird-dashboard", "client ID for dashboard")
	rootCmd.PersistentFlags().StringVar(&config.CLIClientID, "cli-client-id", "netbird-client", "client ID for CLI")

	// Add subcommands
	rootCmd.AddCommand(userCmd)

	setFlagsFromEnvVars(rootCmd)
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func execute(cmd *cobra.Command, args []string) error {
	err := util.InitLog(config.LogLevel, config.LogFile)
	if err != nil {
		return fmt.Errorf("failed to initialize log: %s", err)
	}

	// Set default issuer if not provided
	issuer := config.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", config.ListenPort)
	}

	log.Infof("Starting NetBird Identity Provider")
	log.Infof("  Port: %d", config.ListenPort)
	log.Infof("  Issuer: %s", issuer)
	log.Infof("  Data directory: %s", config.DataDir)
	log.Infof("  Dev mode: %v", config.DevMode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create provider config
	providerConfig := &oidcprovider.Config{
		Issuer:  issuer,
		Port:    config.ListenPort,
		DataDir: config.DataDir,
		DevMode: config.DevMode,
	}

	// Create the provider
	provider, err := oidcprovider.NewProvider(ctx, providerConfig)
	if err != nil {
		return fmt.Errorf("failed to create IdP: %w", err)
	}

	// Ensure default clients exist
	if err := provider.EnsureDefaultClients(ctx, config.DashboardRedirectURIs, config.CLIRedirectURIs); err != nil {
		return fmt.Errorf("failed to create default clients: %w", err)
	}

	// Start the provider
	if err := provider.Start(ctx); err != nil {
		return fmt.Errorf("failed to start IdP: %w", err)
	}

	log.Infof("IdP is running")
	log.Infof("  Discovery: %s/.well-known/openid-configuration", issuer)
	log.Infof("  Authorization: %s/authorize", issuer)
	log.Infof("  Token: %s/oauth/token", issuer)
	log.Infof("  Device authorization: %s/device_authorization", issuer)
	log.Infof("  JWKS: %s/keys", issuer)
	log.Infof("  Login: %s/login", issuer)
	log.Infof("  Device flow: %s/device", issuer)

	// Wait for exit signal
	waitForExitSignal()

	log.Infof("Shutting down IdP...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10)
	defer shutdownCancel()

	if err := provider.Stop(shutdownCtx); err != nil {
		return fmt.Errorf("failed to stop IdP: %w", err)
	}

	log.Infof("IdP stopped")
	return nil
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	<-osSigs
}
