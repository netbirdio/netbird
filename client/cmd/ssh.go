package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/internal"
	sshclient "github.com/netbirdio/netbird/client/ssh/client"
	"github.com/netbirdio/netbird/client/ssh/detection"
	sshproxy "github.com/netbirdio/netbird/client/ssh/proxy"
	sshserver "github.com/netbirdio/netbird/client/ssh/server"
	"github.com/netbirdio/netbird/util"
)

const (
	sshUsernameDesc      = "SSH username"
	hostArgumentRequired = "host argument required"

	serverSSHAllowedFlag           = "allow-server-ssh"
	enableSSHRootFlag              = "enable-ssh-root"
	enableSSHSFTPFlag              = "enable-ssh-sftp"
	enableSSHLocalPortForwardFlag  = "enable-ssh-local-port-forwarding"
	enableSSHRemotePortForwardFlag = "enable-ssh-remote-port-forwarding"
	disableSSHAuthFlag             = "disable-ssh-auth"
	sshJWTCacheTTLFlag             = "ssh-jwt-cache-ttl"
)

var (
	port                  int
	username              string
	host                  string
	command               string
	localForwards         []string
	remoteForwards        []string
	strictHostKeyChecking bool
	knownHostsFile        string
	identityFile          string
	skipCachedToken       bool
	requestPTY            bool
	sshNoBrowser          bool
)

var (
	serverSSHAllowed           bool
	enableSSHRoot              bool
	enableSSHSFTP              bool
	enableSSHLocalPortForward  bool
	enableSSHRemotePortForward bool
	disableSSHAuth             bool
	sshJWTCacheTTL             int
)

func init() {
	upCmd.PersistentFlags().BoolVar(&serverSSHAllowed, serverSSHAllowedFlag, false, "Allow SSH server on peer")
	upCmd.PersistentFlags().BoolVar(&enableSSHRoot, enableSSHRootFlag, false, "Enable root login for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHSFTP, enableSSHSFTPFlag, false, "Enable SFTP subsystem for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHLocalPortForward, enableSSHLocalPortForwardFlag, false, "Enable local port forwarding for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHRemotePortForward, enableSSHRemotePortForwardFlag, false, "Enable remote port forwarding for SSH server")
	upCmd.PersistentFlags().BoolVar(&disableSSHAuth, disableSSHAuthFlag, false, "Disable SSH authentication")
	upCmd.PersistentFlags().IntVar(&sshJWTCacheTTL, sshJWTCacheTTLFlag, 0, "SSH JWT token cache TTL in seconds (0=disabled)")

	sshCmd.PersistentFlags().IntVarP(&port, "port", "p", sshserver.DefaultSSHPort, "Remote SSH port")
	sshCmd.PersistentFlags().StringVarP(&username, "user", "u", "", sshUsernameDesc)
	sshCmd.PersistentFlags().StringVar(&username, "login", "", sshUsernameDesc+" (alias for --user)")
	sshCmd.PersistentFlags().BoolVarP(&requestPTY, "tty", "t", false, "Force pseudo-terminal allocation")
	sshCmd.PersistentFlags().BoolVar(&strictHostKeyChecking, "strict-host-key-checking", true, "Enable strict host key checking (default: true)")
	sshCmd.PersistentFlags().StringVarP(&knownHostsFile, "known-hosts", "o", "", "Path to known_hosts file (default: ~/.ssh/known_hosts)")
	sshCmd.PersistentFlags().StringVarP(&identityFile, "identity", "i", "", "Path to SSH private key file (deprecated)")
	_ = sshCmd.PersistentFlags().MarkDeprecated("identity", "this flag is no longer used")
	sshCmd.PersistentFlags().BoolVar(&skipCachedToken, "no-cache", false, "Skip cached JWT token and force fresh authentication")
	sshCmd.PersistentFlags().BoolVar(&sshNoBrowser, noBrowserFlag, false, noBrowserDesc)

	sshCmd.PersistentFlags().StringArrayP("L", "L", []string{}, "Local port forwarding [bind_address:]port:host:hostport")
	sshCmd.PersistentFlags().StringArrayP("R", "R", []string{}, "Remote port forwarding [bind_address:]port:host:hostport")

	sshCmd.AddCommand(sshSftpCmd)
	sshCmd.AddCommand(sshProxyCmd)
	sshCmd.AddCommand(sshDetectCmd)
}

var sshCmd = &cobra.Command{
	Use:   "ssh [flags] [user@]host [command]",
	Short: "Connect to a NetBird peer via SSH",
	Long: `Connect to a NetBird peer using SSH with support for port forwarding.

Port Forwarding:
  -L [bind_address:]port:host:hostport   Local port forwarding
  -L [bind_address:]port:/path/to/socket Local port forwarding to Unix socket
  -R [bind_address:]port:host:hostport   Remote port forwarding
  -R [bind_address:]port:/path/to/socket Remote port forwarding to Unix socket

SSH Options:
  -p, --port int                       Remote SSH port (default 22)
  -u, --user string                    SSH username
      --login string                   SSH username (alias for --user)
  -t, --tty                            Force pseudo-terminal allocation
      --strict-host-key-checking       Enable strict host key checking (default: true)
  -o, --known-hosts string             Path to known_hosts file

Examples:
  netbird ssh peer-hostname
  netbird ssh root@peer-hostname
  netbird ssh --login root peer-hostname
  netbird ssh peer-hostname ls -la
  netbird ssh peer-hostname whoami
  netbird ssh -t peer-hostname tmux                  # Force PTY for tmux/screen
  netbird ssh -t peer-hostname sudo -i               # Force PTY for interactive sudo
  netbird ssh -L 8080:localhost:80 peer-hostname     # Local port forwarding
  netbird ssh -R 9090:localhost:3000 peer-hostname   # Remote port forwarding
  netbird ssh -L "*:8080:localhost:80" peer-hostname # Bind to all interfaces
  netbird ssh -L 8080:/tmp/socket peer-hostname      # Unix socket forwarding`,
	DisableFlagParsing: true,
	Args:               validateSSHArgsWithoutFlagParsing,
	RunE:               sshFn,
	Aliases:            []string{"ssh"},
}

func sshFn(cmd *cobra.Command, args []string) error {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return cmd.Help()
		}
	}

	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	cmd.SetOut(cmd.OutOrStdout())

	logOutput := "console"
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != defaultLogFile {
		logOutput = firstLogFile
	}
	if err := util.InitLog(logLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	sshctx, cancel := context.WithCancel(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := runSSH(sshctx, host, cmd); err != nil {
			errCh <- err
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
		<-sshctx.Done()
		return nil
	case err := <-errCh:
		return err
	case <-sshctx.Done():
	}

	return nil
}

// getEnvOrDefault checks for environment variables with WT_ and NB_ prefixes
func getEnvOrDefault(flagName, defaultValue string) string {
	if envValue := os.Getenv("WT_" + flagName); envValue != "" {
		return envValue
	}
	if envValue := os.Getenv("NB_" + flagName); envValue != "" {
		return envValue
	}
	return defaultValue
}

// getBoolEnvOrDefault checks for boolean environment variables with WT_ and NB_ prefixes
func getBoolEnvOrDefault(flagName string, defaultValue bool) bool {
	if envValue := os.Getenv("WT_" + flagName); envValue != "" {
		if parsed, err := strconv.ParseBool(envValue); err == nil {
			return parsed
		}
	}
	if envValue := os.Getenv("NB_" + flagName); envValue != "" {
		if parsed, err := strconv.ParseBool(envValue); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// resetSSHGlobals sets SSH globals to their default values
func resetSSHGlobals() {
	port = sshserver.DefaultSSHPort
	username = ""
	host = ""
	command = ""
	localForwards = nil
	remoteForwards = nil
	strictHostKeyChecking = true
	knownHostsFile = ""
	identityFile = ""
	sshNoBrowser = false
}

// parseCustomSSHFlags extracts -L, -R flags and returns filtered args
func parseCustomSSHFlags(args []string) ([]string, []string, []string) {
	var localForwardFlags []string
	var remoteForwardFlags []string
	var filteredArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "-L"):
			localForwardFlags, i = parseForwardFlag(arg, args, i, localForwardFlags)
		case strings.HasPrefix(arg, "-R"):
			remoteForwardFlags, i = parseForwardFlag(arg, args, i, remoteForwardFlags)
		default:
			filteredArgs = append(filteredArgs, arg)
		}
	}

	return filteredArgs, localForwardFlags, remoteForwardFlags
}

func parseForwardFlag(arg string, args []string, i int, flags []string) ([]string, int) {
	if arg == "-L" || arg == "-R" {
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	} else if len(arg) > 2 {
		flags = append(flags, arg[2:])
	}
	return flags, i
}

// extractGlobalFlags parses global flags that were passed before 'ssh' command
func extractGlobalFlags(args []string) {
	sshPos := findSSHCommandPosition(args)
	if sshPos == -1 {
		return
	}

	globalArgs := args[:sshPos]
	parseGlobalArgs(globalArgs)
}

// findSSHCommandPosition locates the 'ssh' command in the argument list
func findSSHCommandPosition(args []string) int {
	for i, arg := range args {
		if arg == "ssh" {
			return i
		}
	}
	return -1
}

const (
	configFlag   = "config"
	logLevelFlag = "log-level"
	logFileFlag  = "log-file"
)

// parseGlobalArgs processes the global arguments and sets the corresponding variables
func parseGlobalArgs(globalArgs []string) {
	flagHandlers := map[string]func(string){
		configFlag:   func(value string) { configPath = value },
		logLevelFlag: func(value string) { logLevel = value },
		logFileFlag: func(value string) {
			if !slices.Contains(logFiles, value) {
				logFiles = append(logFiles, value)
			}
		},
	}

	shortFlags := map[string]string{
		"c": configFlag,
		"l": logLevelFlag,
	}

	for i := 0; i < len(globalArgs); i++ {
		arg := globalArgs[i]

		if handled, nextIndex := parseFlag(arg, globalArgs, i, flagHandlers, shortFlags); handled {
			i = nextIndex
		}
	}
}

// parseFlag handles generic flag parsing for both long and short forms
func parseFlag(arg string, args []string, currentIndex int, flagHandlers map[string]func(string), shortFlags map[string]string) (bool, int) {
	if parsedValue, found := parseEqualsFormat(arg, flagHandlers, shortFlags); found {
		flagHandlers[parsedValue.flagName](parsedValue.value)
		return true, currentIndex
	}

	if parsedValue, found := parseSpacedFormat(arg, args, currentIndex, flagHandlers, shortFlags); found {
		flagHandlers[parsedValue.flagName](parsedValue.value)
		return true, currentIndex + 1
	}

	return false, currentIndex
}

type parsedFlag struct {
	flagName string
	value    string
}

// parseEqualsFormat handles --flag=value and -f=value formats
func parseEqualsFormat(arg string, flagHandlers map[string]func(string), shortFlags map[string]string) (parsedFlag, bool) {
	if !strings.Contains(arg, "=") {
		return parsedFlag{}, false
	}

	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return parsedFlag{}, false
	}

	if strings.HasPrefix(parts[0], "--") {
		flagName := strings.TrimPrefix(parts[0], "--")
		if _, exists := flagHandlers[flagName]; exists {
			return parsedFlag{flagName: flagName, value: parts[1]}, true
		}
	}

	if strings.HasPrefix(parts[0], "-") && len(parts[0]) == 2 {
		shortFlag := strings.TrimPrefix(parts[0], "-")
		if longFlag, exists := shortFlags[shortFlag]; exists {
			if _, exists := flagHandlers[longFlag]; exists {
				return parsedFlag{flagName: longFlag, value: parts[1]}, true
			}
		}
	}

	return parsedFlag{}, false
}

// parseSpacedFormat handles --flag value and -f value formats
func parseSpacedFormat(arg string, args []string, currentIndex int, flagHandlers map[string]func(string), shortFlags map[string]string) (parsedFlag, bool) {
	if currentIndex+1 >= len(args) {
		return parsedFlag{}, false
	}

	if strings.HasPrefix(arg, "--") {
		flagName := strings.TrimPrefix(arg, "--")
		if _, exists := flagHandlers[flagName]; exists {
			return parsedFlag{flagName: flagName, value: args[currentIndex+1]}, true
		}
	}

	if strings.HasPrefix(arg, "-") && len(arg) == 2 {
		shortFlag := strings.TrimPrefix(arg, "-")
		if longFlag, exists := shortFlags[shortFlag]; exists {
			if _, exists := flagHandlers[longFlag]; exists {
				return parsedFlag{flagName: longFlag, value: args[currentIndex+1]}, true
			}
		}
	}

	return parsedFlag{}, false
}

// createSSHFlagSet creates and configures the flag set for SSH command parsing
// sshFlags contains all SSH-related flags and parameters
type sshFlags struct {
	Port                  int
	Username              string
	Login                 string
	RequestPTY            bool
	StrictHostKeyChecking bool
	KnownHostsFile        string
	IdentityFile          string
	SkipCachedToken       bool
	NoBrowser             bool
	ConfigPath            string
	LogLevel              string
	LocalForwards         []string
	RemoteForwards        []string
	Host                  string
	Command               string
}

func createSSHFlagSet() (*flag.FlagSet, *sshFlags) {
	defaultConfigPath := getEnvOrDefault("CONFIG", configPath)
	defaultLogLevel := getEnvOrDefault("LOG_LEVEL", logLevel)
	defaultNoBrowser := getBoolEnvOrDefault("NO_BROWSER", false)

	fs := flag.NewFlagSet("ssh-flags", flag.ContinueOnError)
	fs.SetOutput(nil)

	flags := &sshFlags{}

	fs.IntVar(&flags.Port, "p", sshserver.DefaultSSHPort, "SSH port")
	fs.IntVar(&flags.Port, "port", sshserver.DefaultSSHPort, "SSH port")
	fs.StringVar(&flags.Username, "u", "", sshUsernameDesc)
	fs.StringVar(&flags.Username, "user", "", sshUsernameDesc)
	fs.StringVar(&flags.Login, "login", "", sshUsernameDesc+" (alias for --user)")
	fs.BoolVar(&flags.RequestPTY, "t", false, "Force pseudo-terminal allocation")
	fs.BoolVar(&flags.RequestPTY, "tty", false, "Force pseudo-terminal allocation")

	fs.BoolVar(&flags.StrictHostKeyChecking, "strict-host-key-checking", true, "Enable strict host key checking")
	fs.StringVar(&flags.KnownHostsFile, "o", "", "Path to known_hosts file")
	fs.StringVar(&flags.KnownHostsFile, "known-hosts", "", "Path to known_hosts file")
	fs.StringVar(&flags.IdentityFile, "i", "", "Path to SSH private key file")
	fs.StringVar(&flags.IdentityFile, "identity", "", "Path to SSH private key file")
	fs.BoolVar(&flags.SkipCachedToken, "no-cache", false, "Skip cached JWT token and force fresh authentication")
	fs.BoolVar(&flags.NoBrowser, "no-browser", defaultNoBrowser, noBrowserDesc)

	fs.StringVar(&flags.ConfigPath, "c", defaultConfigPath, "Netbird config file location")
	fs.StringVar(&flags.ConfigPath, "config", defaultConfigPath, "Netbird config file location")
	fs.StringVar(&flags.LogLevel, "l", defaultLogLevel, "sets Netbird log level")
	fs.StringVar(&flags.LogLevel, "log-level", defaultLogLevel, "sets Netbird log level")

	return fs, flags
}

func validateSSHArgsWithoutFlagParsing(_ *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New(hostArgumentRequired)
	}

	resetSSHGlobals()

	if len(os.Args) > 2 {
		extractGlobalFlags(os.Args[1:])
	}

	filteredArgs, localForwardFlags, remoteForwardFlags := parseCustomSSHFlags(args)

	fs, flags := createSSHFlagSet()

	if err := fs.Parse(filteredArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		return errors.New(hostArgumentRequired)
	}

	port = flags.Port
	if flags.Username != "" {
		username = flags.Username
	} else if flags.Login != "" {
		username = flags.Login
	}

	requestPTY = flags.RequestPTY
	strictHostKeyChecking = flags.StrictHostKeyChecking
	knownHostsFile = flags.KnownHostsFile
	identityFile = flags.IdentityFile
	skipCachedToken = flags.SkipCachedToken
	sshNoBrowser = flags.NoBrowser

	if flags.ConfigPath != getEnvOrDefault("CONFIG", configPath) {
		configPath = flags.ConfigPath
	}
	if flags.LogLevel != getEnvOrDefault("LOG_LEVEL", logLevel) {
		logLevel = flags.LogLevel
	}

	localForwards = localForwardFlags
	remoteForwards = remoteForwardFlags

	return parseHostnameAndCommand(remaining)
}

func parseHostnameAndCommand(args []string) error {
	if len(args) < 1 {
		return errors.New(hostArgumentRequired)
	}

	arg := args[0]
	if strings.Contains(arg, "@") {
		parts := strings.SplitN(arg, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("invalid user@host format")
		}
		if username == "" {
			username = parts[0]
		}
		host = parts[1]
	} else {
		host = arg
	}

	if username == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			username = sudoUser
		} else if currentUser, err := user.Current(); err == nil {
			username = currentUser.Username
		} else {
			username = "root"
		}
	}

	// Everything after hostname becomes the command
	if len(args) > 1 {
		command = strings.Join(args[1:], " ")
	}

	return nil
}

func runSSH(ctx context.Context, addr string, cmd *cobra.Command) error {
	target := fmt.Sprintf("%s:%d", addr, port)
	c, err := sshclient.Dial(ctx, target, username, sshclient.DialOptions{
		KnownHostsFile:     knownHostsFile,
		IdentityFile:       identityFile,
		DaemonAddr:         daemonAddr,
		SkipCachedToken:    skipCachedToken,
		InsecureSkipVerify: !strictHostKeyChecking,
		NoBrowser:          sshNoBrowser,
	})

	if err != nil {
		cmd.Printf("Failed to connect to %s@%s\n", username, target)
		cmd.Printf("\nTroubleshooting steps:\n")
		cmd.Printf("  1. Check peer connectivity: netbird status -d\n")
		cmd.Printf("  2. Verify SSH server is enabled on the peer\n")
		cmd.Printf("  3. Ensure correct hostname/IP is used\n")
		return fmt.Errorf("dial %s: %w", target, err)
	}

	sshCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-sshCtx.Done()
		if err := c.Close(); err != nil {
			cmd.Printf("Error closing SSH connection: %v\n", err)
		}
	}()

	if err := startPortForwarding(sshCtx, c, cmd); err != nil {
		return fmt.Errorf("start port forwarding: %w", err)
	}

	if command != "" {
		return executeSSHCommand(sshCtx, c, command)
	}
	return openSSHTerminal(sshCtx, c)
}

// executeSSHCommand executes a command over SSH.
func executeSSHCommand(ctx context.Context, c *sshclient.Client, command string) error {
	var err error
	if requestPTY {
		err = c.ExecuteCommandWithPTY(ctx, command)
	} else {
		err = c.ExecuteCommandWithIO(ctx, command)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}

		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitStatus())
		}

		var exitMissingErr *ssh.ExitMissingError
		if errors.As(err, &exitMissingErr) {
			log.Debugf("Remote command exited without exit status: %v", err)
			return nil
		}

		return fmt.Errorf("execute command: %w", err)
	}
	return nil
}

// openSSHTerminal opens an interactive SSH terminal.
func openSSHTerminal(ctx context.Context, c *sshclient.Client) error {
	if err := c.OpenTerminal(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}

		var exitMissingErr *ssh.ExitMissingError
		if errors.As(err, &exitMissingErr) {
			log.Debugf("Remote terminal exited without exit status: %v", err)
			return nil
		}

		return fmt.Errorf("open terminal: %w", err)
	}
	return nil
}

// startPortForwarding starts local and remote port forwarding based on command line flags
func startPortForwarding(ctx context.Context, c *sshclient.Client, cmd *cobra.Command) error {
	for _, forward := range localForwards {
		if err := parseAndStartLocalForward(ctx, c, forward, cmd); err != nil {
			return fmt.Errorf("local port forward %s: %w", forward, err)
		}
	}

	for _, forward := range remoteForwards {
		if err := parseAndStartRemoteForward(ctx, c, forward, cmd); err != nil {
			return fmt.Errorf("remote port forward %s: %w", forward, err)
		}
	}

	return nil
}

// parseAndStartLocalForward parses and starts a local port forward (-L)
func parseAndStartLocalForward(ctx context.Context, c *sshclient.Client, forward string, cmd *cobra.Command) error {
	localAddr, remoteAddr, err := parsePortForwardSpec(forward)
	if err != nil {
		return err
	}

	if err := validateDestinationPort(remoteAddr); err != nil {
		return fmt.Errorf("invalid remote address: %w", err)
	}

	log.Debugf("Local port forwarding: %s -> %s", localAddr, remoteAddr)

	go func() {
		if err := c.LocalPortForward(ctx, localAddr, remoteAddr); err != nil && !errors.Is(err, context.Canceled) {
			cmd.Printf("Local port forward error: %v\n", err)
		}
	}()

	return nil
}

// parseAndStartRemoteForward parses and starts a remote port forward (-R)
func parseAndStartRemoteForward(ctx context.Context, c *sshclient.Client, forward string, cmd *cobra.Command) error {
	remoteAddr, localAddr, err := parsePortForwardSpec(forward)
	if err != nil {
		return err
	}

	if err := validateDestinationPort(localAddr); err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	log.Debugf("Remote port forwarding: %s -> %s", remoteAddr, localAddr)

	go func() {
		if err := c.RemotePortForward(ctx, remoteAddr, localAddr); err != nil && !errors.Is(err, context.Canceled) {
			cmd.Printf("Remote port forward error: %v\n", err)
		}
	}()

	return nil
}

// validateDestinationPort checks that the destination address has a valid port.
// Port 0 is only valid for bind addresses (where the OS picks an available port),
// not for destination addresses where we need to connect.
func validateDestinationPort(addr string) error {
	if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "./") {
		return nil
	}

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse address %s: %w", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %s: %w", portStr, err)
	}

	if port == 0 {
		return fmt.Errorf("port 0 is not valid for destination address")
	}

	if port < 0 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}

	return nil
}

// parsePortForwardSpec parses port forward specifications like "8080:localhost:80" or "[::1]:8080:localhost:80".
// Also supports Unix sockets like "8080:/tmp/socket" or "127.0.0.1:8080:/tmp/socket".
func parsePortForwardSpec(spec string) (string, string, error) {
	// Support formats:
	// port:host:hostport  -> localhost:port -> host:hostport
	// host:port:host:hostport  -> host:port -> host:hostport
	// [host]:port:host:hostport -> [host]:port -> host:hostport
	// port:unix_socket_path -> localhost:port -> unix_socket_path
	// host:port:unix_socket_path -> host:port -> unix_socket_path

	if strings.HasPrefix(spec, "[") && strings.Contains(spec, "]:") {
		return parseIPv6ForwardSpec(spec)
	}

	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid port forward specification: %s (expected format: [local_host:]local_port:remote_target)", spec)
	}

	switch len(parts) {
	case 2:
		return parseTwoPartForwardSpec(parts, spec)
	case 3:
		return parseThreePartForwardSpec(parts)
	case 4:
		return parseFourPartForwardSpec(parts)
	default:
		return "", "", fmt.Errorf("invalid port forward specification: %s", spec)
	}
}

// parseTwoPartForwardSpec handles "port:unix_socket" format.
func parseTwoPartForwardSpec(parts []string, spec string) (string, string, error) {
	if isUnixSocket(parts[1]) {
		localAddr := "localhost:" + parts[0]
		remoteAddr := parts[1]
		return localAddr, remoteAddr, nil
	}
	return "", "", fmt.Errorf("invalid port forward specification: %s (expected format: [local_host:]local_port:remote_host:remote_port or [local_host:]local_port:unix_socket)", spec)
}

// parseThreePartForwardSpec handles "port:host:hostport" or "host:port:unix_socket" formats.
func parseThreePartForwardSpec(parts []string) (string, string, error) {
	if isUnixSocket(parts[2]) {
		localHost := normalizeLocalHost(parts[0])
		localAddr := localHost + ":" + parts[1]
		remoteAddr := parts[2]
		return localAddr, remoteAddr, nil
	}
	localAddr := "localhost:" + parts[0]
	remoteAddr := parts[1] + ":" + parts[2]
	return localAddr, remoteAddr, nil
}

// parseFourPartForwardSpec handles "host:port:host:hostport" format.
func parseFourPartForwardSpec(parts []string) (string, string, error) {
	localHost := normalizeLocalHost(parts[0])
	localAddr := localHost + ":" + parts[1]
	remoteAddr := parts[2] + ":" + parts[3]
	return localAddr, remoteAddr, nil
}

// parseIPv6ForwardSpec handles "[host]:port:host:hostport" format.
func parseIPv6ForwardSpec(spec string) (string, string, error) {
	idx := strings.Index(spec, "]:")
	if idx == -1 {
		return "", "", fmt.Errorf("invalid IPv6 port forward specification: %s", spec)
	}

	ipv6Host := spec[:idx+1]
	remaining := spec[idx+2:]

	parts := strings.Split(remaining, ":")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid IPv6 port forward specification: %s (expected [ipv6]:port:host:hostport)", spec)
	}

	localAddr := ipv6Host + ":" + parts[0]
	remoteAddr := parts[1] + ":" + parts[2]
	return localAddr, remoteAddr, nil
}

// isUnixSocket checks if a path is a Unix socket path.
func isUnixSocket(path string) bool {
	return strings.HasPrefix(path, "/") || strings.HasPrefix(path, "./")
}

// normalizeLocalHost converts "*" to "0.0.0.0" for binding to all interfaces.
func normalizeLocalHost(host string) string {
	if host == "*" {
		return "0.0.0.0"
	}
	return host
}

var sshProxyCmd = &cobra.Command{
	Use:    "proxy <host> <port>",
	Short:  "Internal SSH proxy for native SSH client integration",
	Long:   "Internal command used by SSH ProxyCommand to handle JWT authentication",
	Hidden: true,
	Args:   cobra.ExactArgs(2),
	RunE:   sshProxyFn,
}

func sshProxyFn(cmd *cobra.Command, args []string) error {
	logOutput := "console"
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != defaultLogFile {
		logOutput = firstLogFile
	}

	proxyLogLevel := getEnvOrDefault("LOG_LEVEL", logLevel)
	if err := util.InitLog(proxyLogLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	host := args[0]
	portStr := args[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	// Check env var for browser setting since this command is invoked via SSH ProxyCommand
	// where command-line flags cannot be passed. Default is to open browser.
	noBrowser := getBoolEnvOrDefault("NO_BROWSER", false)
	var browserOpener func(string) error
	if !noBrowser {
		browserOpener = util.OpenBrowser
	}

	proxy, err := sshproxy.New(daemonAddr, host, port, cmd.ErrOrStderr(), browserOpener)
	if err != nil {
		return fmt.Errorf("create SSH proxy: %w", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			log.Debugf("close SSH proxy: %v", err)
		}
	}()

	if err := proxy.Connect(cmd.Context()); err != nil {
		return fmt.Errorf("SSH proxy: %w", err)
	}

	return nil
}

var sshDetectCmd = &cobra.Command{
	Use:    "detect <host> <port>",
	Short:  "Detect if a host is running NetBird SSH",
	Long:   "Internal command used by SSH Match exec to detect NetBird SSH servers. Exit codes: 0=JWT, 1=no-JWT, 2=regular SSH",
	Hidden: true,
	Args:   cobra.ExactArgs(2),
	RunE:   sshDetectFn,
}

func sshDetectFn(cmd *cobra.Command, args []string) error {
	detectLogLevel := getEnvOrDefault("LOG_LEVEL", logLevel)
	if err := util.InitLog(detectLogLevel, "console"); err != nil {
		os.Exit(detection.ServerTypeRegular.ExitCode())
	}

	host := args[0]
	portStr := args[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Debugf("invalid port %q: %v", portStr, err)
		os.Exit(detection.ServerTypeRegular.ExitCode())
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), detection.DefaultTimeout)

	dialer := &net.Dialer{}
	serverType, err := detection.DetectSSHServerType(ctx, dialer, host, port)
	if err != nil {
		log.Debugf("SSH server detection failed: %v", err)
		cancel()
		os.Exit(detection.ServerTypeRegular.ExitCode())
	}

	cancel()
	os.Exit(serverType.ExitCode())
	return nil
}
