package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
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

const (
	externalIPMapFlag       = "external-ip-map"
	dnsResolverAddress      = "dns-resolver-address"
	enableRosenpassFlag     = "enable-rosenpass"
	rosenpassPermissiveFlag = "rosenpass-permissive"
	preSharedKeyFlag        = "preshared-key"
	interfaceNameFlag       = "interface-name"
	wireguardPortFlag       = "wireguard-port"
	networkMonitorFlag      = "network-monitor"
	disableAutoConnectFlag  = "disable-auto-connect"
	serverSSHAllowedFlag    = "allow-server-ssh"
	extraIFaceBlackListFlag = "extra-iface-blacklist"
)

var (
	configPath              string
	defaultConfigPathDir    string
	defaultConfigPath       string
	oldDefaultConfigPathDir string
	oldDefaultConfigPath    string
	logLevel                string
	defaultLogFileDir       string
	defaultLogFile          string
	oldDefaultLogFileDir    string
	oldDefaultLogFile       string
	logFile                 string
	daemonAddr              string
	managementURL           string
	adminURL                string
	setupKey                string
	hostName                string
	preSharedKey            string
	natExternalIPs          []string
	customDNSAddress        string
	rosenpassEnabled        bool
	rosenpassPermissive     bool
	serverSSHAllowed        bool
	interfaceName           string
	wireguardPort           uint16
	networkMonitor          bool
	serviceName             string
	autoConnectDisabled     bool
	extraIFaceBlackList     []string
	anonymizeFlag           bool
	rootCmd                 = &cobra.Command{
		Use:          "netbird",
		Short:        "",
		Long:         "",
		SilenceUsage: true,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	defaultConfigPathDir = "/etc/netbird/"
	defaultLogFileDir = "/var/log/netbird/"

	oldDefaultConfigPathDir = "/etc/wiretrustee/"
	oldDefaultLogFileDir = "/var/log/wiretrustee/"

	if runtime.GOOS == "windows" {
		defaultConfigPathDir = os.Getenv("PROGRAMDATA") + "\\Netbird\\"
		defaultLogFileDir = os.Getenv("PROGRAMDATA") + "\\Netbird\\"

		oldDefaultConfigPathDir = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\"
		oldDefaultLogFileDir = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\"
	}

	defaultConfigPath = defaultConfigPathDir + "config.json"
	defaultLogFile = defaultLogFileDir + "client.log"

	oldDefaultConfigPath = oldDefaultConfigPathDir + "config.json"
	oldDefaultLogFile = oldDefaultLogFileDir + "client.log"

	defaultDaemonAddr := "unix:///var/run/netbird.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}

	defaultServiceName := "netbird"
	if runtime.GOOS == "windows" {
		defaultServiceName = "Netbird"
	}

	rootCmd.PersistentFlags().StringVar(&daemonAddr, "daemon-addr", defaultDaemonAddr, "Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")
	rootCmd.PersistentFlags().StringVarP(&managementURL, "management-url", "m", "", fmt.Sprintf("Management Service URL [http|https]://[host]:[port] (default \"%s\")", internal.DefaultManagementURL))
	rootCmd.PersistentFlags().StringVar(&adminURL, "admin-url", "", fmt.Sprintf("Admin Panel URL [http|https]://[host]:[port] (default \"%s\")", internal.DefaultAdminURL))
	rootCmd.PersistentFlags().StringVarP(&serviceName, "service", "s", defaultServiceName, "Netbird system service name")
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Netbird config file location")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "sets Netbird log level")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Netbird log path. If console is specified the log will be output to stdout")
	rootCmd.PersistentFlags().StringVarP(&setupKey, "setup-key", "k", "", "Setup key obtained from the Management Service Dashboard (used to register peer)")
	rootCmd.PersistentFlags().StringVar(&preSharedKey, preSharedKeyFlag, "", "Sets Wireguard PreSharedKey property. If set, then only peers that have the same key can communicate.")
	rootCmd.PersistentFlags().StringVarP(&hostName, "hostname", "n", "", "Sets a custom hostname for the device")
	rootCmd.PersistentFlags().BoolVarP(&anonymizeFlag, "anonymize", "A", false, "anonymize IP addresses and non-netbird.io domains in logs and status output")

	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(downCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(routesCmd)
	rootCmd.AddCommand(debugCmd)

	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd) // service control commands are subcommands of service
	serviceCmd.AddCommand(installCmd, uninstallCmd)              // service installer commands are subcommands of service

	routesCmd.AddCommand(routesListCmd)
	routesCmd.AddCommand(routesSelectCmd, routesDeselectCmd)

	debugCmd.AddCommand(debugBundleCmd)
	debugCmd.AddCommand(logCmd)
	logCmd.AddCommand(logLevelCmd)
	debugCmd.AddCommand(forCmd)

	upCmd.PersistentFlags().StringSliceVar(&natExternalIPs, externalIPMapFlag, nil,
		`Sets external IPs maps between local addresses and interfaces.`+
			`You can specify a comma-separated list with a single IP and IP/IP or IP/Interface Name. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --external-ip-map 12.34.56.78/10.0.0.1 or --external-ip-map 12.34.56.200,12.34.56.78/10.0.0.1,12.34.56.80/eth1 `+
			`or --external-ip-map ""`,
	)
	upCmd.PersistentFlags().StringVar(&customDNSAddress, dnsResolverAddress, "",
		`Sets a custom address for NetBird's local DNS resolver. `+
			`If set, the agent won't attempt to discover the best ip and port to listen on. `+
			`An empty string "" clears the previous configuration. `+
			`E.g. --dns-resolver-address 127.0.0.1:5053 or --dns-resolver-address ""`,
	)
	upCmd.PersistentFlags().BoolVar(&rosenpassEnabled, enableRosenpassFlag, false, "[Experimental] Enable Rosenpass feature. If enabled, the connection will be post-quantum secured via Rosenpass.")
	upCmd.PersistentFlags().BoolVar(&rosenpassPermissive, rosenpassPermissiveFlag, false, "[Experimental] Enable Rosenpass in permissive mode to allow this peer to accept WireGuard connections without requiring Rosenpass functionality from peers that do not have Rosenpass enabled.")
	upCmd.PersistentFlags().BoolVar(&serverSSHAllowed, serverSSHAllowedFlag, false, "Allow SSH server on peer. If enabled, the SSH server will be permitted")
	upCmd.PersistentFlags().BoolVar(&autoConnectDisabled, disableAutoConnectFlag, false, "Disables auto-connect feature. If enabled, then the client won't connect automatically when the service starts.")
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
func SetFlagsFromEnvVars(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.VisitAll(func(f *pflag.Flag) {
		oldEnvVar := FlagNameToEnvVar(f.Name, "WT_")

		if value, present := os.LookupEnv(oldEnvVar); present {
			err := flags.Set(f.Name, value)
			if err != nil {
				log.Infof("unable to configure flag %s using variable %s, err: %v", f.Name, oldEnvVar, err)
			}
		}

		newEnvVar := FlagNameToEnvVar(f.Name, "NB_")

		if value, present := os.LookupEnv(newEnvVar); present {
			err := flags.Set(f.Name, value)
			if err != nil {
				log.Infof("unable to configure flag %s using variable %s, err: %v", f.Name, newEnvVar, err)
			}
		}
	})
}

// FlagNameToEnvVar converts flag name to environment var name adding a prefix,
// replacing dashes and making all uppercase (e.g. setup-keys is converted to NB_SETUP_KEYS according to the input prefix)
func FlagNameToEnvVar(cmdFlag string, prefix string) string {
	parsed := strings.ReplaceAll(cmdFlag, "-", "_")
	upper := strings.ToUpper(parsed)
	return prefix + upper
}

// DialClientGRPCServer returns client connection to the daemon server.
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

func handleRebrand(cmd *cobra.Command) error {
	var err error
	if logFile == defaultLogFile {
		if migrateToNetbird(oldDefaultLogFile, defaultLogFile) {
			cmd.Printf("will copy Log dir %s and its content to %s\n", oldDefaultLogFileDir, defaultLogFileDir)
			err = cpDir(oldDefaultLogFileDir, defaultLogFileDir)
			if err != nil {
				return err
			}
		}
	}
	if configPath == defaultConfigPath {
		if migrateToNetbird(oldDefaultConfigPath, defaultConfigPath) {
			cmd.Printf("will copy Config dir %s and its content to %s\n", oldDefaultConfigPathDir, defaultConfigPathDir)
			err = cpDir(oldDefaultConfigPathDir, defaultConfigPathDir)
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
			return fmt.Errorf("fouldn't get fileInfo; %v", err)
		}

		switch fileInfo.Mode() & os.ModeType {
		case os.ModeSymlink:
			if err = copySymLink(srcfp, dstfp); err != nil {
				return fmt.Errorf("failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		case os.ModeDir:
			if err = cpDir(srcfp, dstfp); err != nil {
				return fmt.Errorf("failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		default:
			if err = cpFile(srcfp, dstfp); err != nil {
				return fmt.Errorf("failed to copy from %s to %s; %v", srcfp, dstfp, err)
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

func getClient(cmd *cobra.Command) (*grpc.ClientConn, error) {
	SetFlagsFromEnvVars(rootCmd)
	cmd.SetOut(cmd.OutOrStdout())

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}

	return conn, nil
}
