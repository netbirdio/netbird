package cmd

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/version"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed = 1
)

var (
	dnsDomain                string
	mgmtDataDir              string
	mgmtConfig               string
	logLevel                 string
	logFile                  string
	disableMetrics           bool
	disableSingleAccMode     bool
	idpSignKeyRefreshEnabled bool

	rootCmd = &cobra.Command{
		Use:          "netbird-mgmt",
		Short:        "",
		Long:         "",
		Version:      version.NetbirdVersion(),
		SilenceUsage: true,
	}

	// Execution control channel for stopCh signal
	stopCh chan int
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	stopCh = make(chan int)
	mgmtCmd.Flags().IntVar(&mgmtPort, "port", 80, "server port to listen on (defaults to 443 if TLS is enabled, 80 otherwise")
	mgmtCmd.Flags().IntVar(&mgmtMetricsPort, "metrics-port", 8081, "metrics endpoint http port. Metrics are accessible under host:metrics-port/metrics")
	mgmtCmd.Flags().StringVar(&mgmtDataDir, "datadir", defaultMgmtDataDir, "server data directory location")
	mgmtCmd.Flags().StringVar(&mgmtConfig, "config", defaultMgmtConfig, "Netbird config file location. Config params specified via command line (e.g. datadir) have a precedence over configuration from this file")
	mgmtCmd.Flags().StringVar(&mgmtLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
	mgmtCmd.Flags().StringVar(&mgmtSingleAccModeDomain, "single-account-mode-domain", defaultSingleAccModeDomain, "Enables single account mode. This means that all the users will be under the same account grouped by the specified domain. If the installation has more than one account, the property is ineffective. Enabled by default with the default domain "+defaultSingleAccModeDomain)
	mgmtCmd.Flags().BoolVar(&disableSingleAccMode, "disable-single-account-mode", false, "If set to true, disables single account mode. The --single-account-mode-domain property will be ignored and every new user will have a separate NetBird account.")
	mgmtCmd.Flags().StringVar(&certFile, "cert-file", "", "Location of your SSL certificate. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect")
	mgmtCmd.Flags().StringVar(&certKey, "cert-key", "", "Location of your SSL certificate private key. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect")
	mgmtCmd.Flags().BoolVar(&disableMetrics, "disable-anonymous-metrics", false, "disables push of anonymous usage metrics to NetBird")
	mgmtCmd.Flags().StringVar(&dnsDomain, "dns-domain", defaultSingleAccModeDomain, fmt.Sprintf("Domain used for peer resolution. This is appended to the peer's name, e.g. pi-server. %s. Max lenght is 192 characters to allow appending to a peer name with up to 63 characters.", defaultSingleAccModeDomain))
	mgmtCmd.Flags().BoolVar(&idpSignKeyRefreshEnabled, "idp-sign-key-refresh-enabled", false, "Enable cache headers evaluation to determine signing key rotation period. This will refresh the signing key upon expiry.")
	rootCmd.MarkFlagRequired("config") //nolint

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Netbird log path. If console is specified the the log will be output to stdout")
	rootCmd.AddCommand(mgmtCmd)
}

// SetupCloseHandler handles SIGTERM signal and exits with success
func SetupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			stopCh <- 0
		}
	}()
}
