package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/internal"
)

var (
	configPath        string
	defaultConfigPath string
	logLevel          string
	defaultLogFile    string
	logFile           string
	daemonAddr        string
	managementURL     string
	adminURL          string
	setupKey          string
	ssoLogin          bool
	preSharedKey      string
	rootCmd           = &cobra.Command{
		Use:   "wiretrustee",
		Short: "",
		Long:  "",
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	defaultConfigPath = "/etc/wiretrustee/config.json"
	defaultLogFile = "/var/log/wiretrustee/client.log"
	if runtime.GOOS == "windows" {
		defaultConfigPath = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "config.json"
		defaultLogFile = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "client.log"
	}

	defaultDaemonAddr := "unix:///var/run/wiretrustee.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}
	rootCmd.PersistentFlags().StringVar(&daemonAddr, "daemon-addr", defaultDaemonAddr, "Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")
	rootCmd.PersistentFlags().StringVar(&managementURL, "management-url", "", fmt.Sprintf("Management Service URL [http|https]://[host]:[port] (default \"%s\")", internal.ManagementURLDefault().String()))
	rootCmd.PersistentFlags().StringVar(&adminURL, "admin-url", "https://app.netbird.io", "Admin Panel URL [http|https]://[host]:[port]")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Wiretrustee config file location")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "sets Wiretrustee log level")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Wiretrustee log path. If console is specified the the log will be output to stdout")
	rootCmd.PersistentFlags().StringVar(&setupKey, "setup-key", "", "Setup key obtained from the Management Service Dashboard (used to register peer)")
	rootCmd.PersistentFlags().StringVar(&preSharedKey, "preshared-key", "", "Sets Wireguard PreSharedKey property. If set, then only peers that have the same key can communicate.")
	rootCmd.PersistentFlags().BoolVar(&ssoLogin, "sso", false, "Uses the SSO login with provider set in the management server.")
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(downCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(versionCmd)
	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd) // service control commands are subcommands of service
	serviceCmd.AddCommand(installCmd, uninstallCmd)              // service installer commands are subcommands of service
}

// SetupCloseHandler handles SIGTERM signal and exits with success
func SetupCloseHandler(ctx context.Context, cancel context.CancelFunc) {
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		done := ctx.Done()
		select {
		case <-done:
		case <-termCh:
		}

		log.Info("shutdown signal received")
		cancel()
	}()
}

// SetFlagsFromEnvVars reads and updates flag values from environment variables with prefix WT_
func SetFlagsFromEnvVars() {
	flags := rootCmd.PersistentFlags()
	flags.VisitAll(func(f *pflag.Flag) {
		envVar := FlagNameToEnvVar(f.Name)

		if value, present := os.LookupEnv(envVar); present {
			err := flags.Set(f.Name, value)
			if err != nil {
				log.Infof("unable to configure flag %s using variable %s, err: %v", f.Name, envVar, err)
			}
		}
	})
}

// FlagNameToEnvVar converts flag name to environment var name adding a prefix,
// replacing dashes and making all uppercase (e.g. setup-keys is converted to WT_SETUP_KEYS)
func FlagNameToEnvVar(f string) string {
	prefix := "WT_"
	parsed := strings.ReplaceAll(f, "-", "_")
	upper := strings.ToUpper(parsed)
	return prefix + upper
}

// DialClientGRPCServer returns client connection to the dameno server.
func DialClientGRPCServer(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()

	return grpc.DialContext(
		ctx,
		strings.TrimPrefix(addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

// WithBackOff execute function in backoff cycle.
func WithBackOff(bf func() error) error {
	return backoff.RetryNotify(bf, CLIBackOffSettings, func(err error, duration time.Duration) {
		log.Warnf("retrying Login to the Management service in %v due to error %v", duration, err)
	})
}

// CLIBackOffSettings is default backoff settings for CLI commands.
var CLIBackOffSettings = &backoff.ExponentialBackOff{
	InitialInterval:     time.Second,
	RandomizationFactor: backoff.DefaultRandomizationFactor,
	Multiplier:          backoff.DefaultMultiplier,
	MaxInterval:         10 * time.Second,
	MaxElapsedTime:      30 * time.Second,
	Stop:                backoff.Stop,
	Clock:               backoff.SystemClock,
}
