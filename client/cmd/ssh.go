package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

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
)

var (
	serverSSHAllowed           bool
	enableSSHRoot              bool
	enableSSHSFTP              bool
	enableSSHLocalPortForward  bool
	enableSSHRemotePortForward bool
)

func init() {
	upCmd.PersistentFlags().BoolVar(&serverSSHAllowed, serverSSHAllowedFlag, false, "Allow SSH server on peer")
	upCmd.PersistentFlags().BoolVar(&enableSSHRoot, enableSSHRootFlag, false, "Enable root login for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHSFTP, enableSSHSFTPFlag, false, "Enable SFTP subsystem for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHLocalPortForward, enableSSHLocalPortForwardFlag, false, "Enable local port forwarding for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHRemotePortForward, enableSSHRemotePortForwardFlag, false, "Enable remote port forwarding for SSH server")

	sshCmd.PersistentFlags().IntVarP(&port, "port", "p", sshserver.DefaultSSHPort, "Remote SSH port")
	sshCmd.PersistentFlags().StringVarP(&username, "user", "u", "", sshUsernameDesc)
	sshCmd.PersistentFlags().StringVar(&username, "login", "", sshUsernameDesc+" (alias for --user)")
	sshCmd.PersistentFlags().BoolVar(&strictHostKeyChecking, "strict-host-key-checking", true, "Enable strict host key checking (default: true)")
	sshCmd.PersistentFlags().StringVarP(&knownHostsFile, "known-hosts", "o", "", "Path to known_hosts file (default: ~/.ssh/known_hosts)")
	sshCmd.PersistentFlags().StringVarP(&identityFile, "identity", "i", "", "Path to SSH private key file")
	sshCmd.PersistentFlags().BoolVar(&skipCachedToken, "no-cache", false, "Skip cached JWT token and force fresh authentication")

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
      --strict-host-key-checking       Enable strict host key checking (default: true)
  -o, --known-hosts string             Path to known_hosts file
  -i, --identity string                Path to SSH private key file

Examples:
  netbird ssh peer-hostname
  netbird ssh root@peer-hostname
  netbird ssh --login root peer-hostname
  netbird ssh peer-hostname ls -la
  netbird ssh peer-hostname whoami
  netbird ssh -L 8080:localhost:80 peer-hostname    # Local port forwarding
  netbird ssh -R 9090:localhost:3000 peer-hostname  # Remote port forwarding
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
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != "/var/log/netbird/client.log" {
		logOutput = firstLogFile
	}
	if err := util.InitLog(logLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	sshctx, cancel := context.WithCancel(ctx)

	go func() {
		if err := runSSH(sshctx, host, cmd); err != nil {
			cmd.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
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
func createSSHFlagSet() (*flag.FlagSet, *int, *string, *string, *bool, *string, *string, *bool, *string, *string) {
	defaultConfigPath := getEnvOrDefault("CONFIG", configPath)
	defaultLogLevel := getEnvOrDefault("LOG_LEVEL", logLevel)

	fs := flag.NewFlagSet("ssh-flags", flag.ContinueOnError)
	fs.SetOutput(nil)

	portFlag := fs.Int("p", sshserver.DefaultSSHPort, "SSH port")
	fs.Int("port", sshserver.DefaultSSHPort, "SSH port")
	userFlag := fs.String("u", "", sshUsernameDesc)
	fs.String("user", "", sshUsernameDesc)
	loginFlag := fs.String("login", "", sshUsernameDesc+" (alias for --user)")

	strictHostKeyCheckingFlag := fs.Bool("strict-host-key-checking", true, "Enable strict host key checking")
	knownHostsFlag := fs.String("o", "", "Path to known_hosts file")
	fs.String("known-hosts", "", "Path to known_hosts file")
	identityFlag := fs.String("i", "", "Path to SSH private key file")
	fs.String("identity", "", "Path to SSH private key file")
	noCacheFlag := fs.Bool("no-cache", false, "Skip cached JWT token and force fresh authentication")

	configFlag := fs.String("c", defaultConfigPath, "Netbird config file location")
	fs.String("config", defaultConfigPath, "Netbird config file location")
	logLevelFlag := fs.String("l", defaultLogLevel, "sets Netbird log level")
	fs.String("log-level", defaultLogLevel, "sets Netbird log level")

	return fs, portFlag, userFlag, loginFlag, strictHostKeyCheckingFlag, knownHostsFlag, identityFlag, noCacheFlag, configFlag, logLevelFlag
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

	fs, portFlag, userFlag, loginFlag, strictHostKeyCheckingFlag, knownHostsFlag, identityFlag, noCacheFlag, configFlag, logLevelFlag := createSSHFlagSet()

	if err := fs.Parse(filteredArgs); err != nil {
		return parseHostnameAndCommand(filteredArgs)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		return errors.New(hostArgumentRequired)
	}

	port = *portFlag
	if *userFlag != "" {
		username = *userFlag
	} else if *loginFlag != "" {
		username = *loginFlag
	}

	strictHostKeyChecking = *strictHostKeyCheckingFlag
	knownHostsFile = *knownHostsFlag
	identityFile = *identityFlag
	skipCachedToken = *noCacheFlag

	if *configFlag != getEnvOrDefault("CONFIG", configPath) {
		configPath = *configFlag
	}
	if *logLevelFlag != getEnvOrDefault("LOG_LEVEL", logLevel) {
		logLevel = *logLevelFlag
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
	if err := c.ExecuteCommandWithIO(ctx, command); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
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

	cmd.Printf("Local port forwarding: %s -> %s\n", localAddr, remoteAddr)

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

	cmd.Printf("Remote port forwarding: %s -> %s\n", remoteAddr, localAddr)

	go func() {
		if err := c.RemotePortForward(ctx, remoteAddr, localAddr); err != nil && !errors.Is(err, context.Canceled) {
			cmd.Printf("Remote port forward error: %v\n", err)
		}
	}()

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
	host := args[0]
	portStr := args[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	proxy, err := sshproxy.New(daemonAddr, host, port, cmd.ErrOrStderr())
	if err != nil {
		return fmt.Errorf("create SSH proxy: %w", err)
	}

	ctx := context.Background()
	if err := proxy.Connect(ctx); err != nil {
		return fmt.Errorf("SSH proxy: %w", err)
	}

	return nil
}

var sshDetectCmd = &cobra.Command{
	Use:    "detect <host> <port>",
	Short:  "Detect if a host is running NetBird SSH",
	Long:   "Internal command used by SSH Match exec to detect NetBird SSH servers",
	Hidden: true,
	Args:   cobra.ExactArgs(2),
	RunE:   sshDetectFn,
}

func sshDetectFn(_ *cobra.Command, args []string) error {
	host := args[0]
	portStr := args[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("not netbird")
	}

	username := ""
	if currentUser, err := user.Current(); err == nil {
		username = currentUser.Username
	}

	serverType, err := detection.DetectSSHServerType(host, port, username)
	if err != nil {
		return errors.New("not netbird")
	}

	if serverType == detection.ServerTypeNetBirdJWT || serverType == detection.ServerTypeNetBirdNoJWT {
		return nil
	}

	return errors.New("not netbird")
}
