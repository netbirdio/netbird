package link

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// envPrefix matches the prefix the agent uses, so an operator who already sets
// NB_SETUP_KEY or NB_MANAGEMENT_URL for the agent can reuse them here.
const envPrefix = "NB_"

// fileScheme marks a flag value that holds a path to read the real value from,
// so a container can pass a secret as a mounted file instead of an environment
// variable visible to anything that can read the process environment.
const fileScheme = "file:"

// hostnamePattern matches a DNS name per RFC 1123 section 2.1: dot-separated
// labels of letters, digits and inner hyphens.
var hostnamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Config is the resolved runtime configuration.
type Config struct {
	Forwards        []Forward
	AllowedHosts    []string
	SetupKey        string
	ManagementURL   string
	Hostname        string
	StateDir        string
	LogLevel        string
	AllowPublicBind bool
	NoBrowser       bool
	Check           bool
}

// rawConfig holds flag values before parsing and validation.
type rawConfig struct {
	forwards        []string
	allowedHosts    []string
	setupKey        string
	managementURL   string
	hostname        string
	stateDir        string
	logLevel        string
	allowPublicBind bool
	noBrowser       bool
	check           bool
}

// BindFlags registers nblink's flags on cmd and returns the backing values.
// Every flag gains an NB_-prefixed environment variable of the same name, so
// the container configuration cannot drift from the command line.
func BindFlags(cmd *cobra.Command) *rawConfig {
	raw := &rawConfig{}
	f := cmd.PersistentFlags()

	f.StringSliceVar(&raw.forwards, "forward", nil,
		"forward spec scheme://[host:]port=upstream, repeatable (env: comma separated)")
	f.StringSliceVar(&raw.allowedHosts, "allowed-host", nil,
		"extra name a listener may be reached under, repeatable (env: comma separated)")
	f.StringVar(&raw.setupKey, "setup-key", "",
		"setup key for non-interactive login, accepts a file: prefix")
	f.StringVar(&raw.managementURL, "management-url", profilemanager.DefaultManagementURL,
		"management server URL")
	f.StringVar(&raw.hostname, "hostname", "", "peer name in the network")
	f.StringVar(&raw.stateDir, "state-dir", "",
		"directory for config and state, kept in memory when empty")
	f.StringVar(&raw.logLevel, "log-level", "info", "log level")
	f.BoolVar(&raw.allowPublicBind, "allow-public-bind", false,
		"permit forwards that bind an address other than loopback")
	f.BoolVar(&raw.noBrowser, "no-browser", false,
		"print the login URL instead of opening a browser")
	f.BoolVar(&raw.check, "check", false,
		"validate configuration, print the effective forwards and exit")

	return raw
}

// SetFlagsFromEnvVars fills unset flags from NB_-prefixed environment
// variables derived from each flag name, so --management-url reads
// NB_MANAGEMENT_URL. A flag given on the command line wins.
//
// A value that does not parse is an error rather than a warning, so a
// container cannot start with a configuration other than the one it was given.
func SetFlagsFromEnvVars(cmd *cobra.Command) error {
	flags := cmd.PersistentFlags()
	var err error
	flags.VisitAll(func(f *pflag.Flag) {
		if err != nil || f.Changed {
			return
		}
		env := FlagNameToEnvVar(f.Name)
		value, ok := os.LookupEnv(env)
		if !ok {
			return
		}
		if setErr := flags.Set(f.Name, value); setErr != nil {
			err = fmt.Errorf("%s: %w", env, setErr)
		}
	})
	return err
}

// FlagNameToEnvVar converts a flag name to its environment variable, so
// allow-public-bind becomes NB_ALLOW_PUBLIC_BIND.
func FlagNameToEnvVar(name string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// Resolve validates the raw flag values and produces a runtime configuration.
// It reports every problem it can rather than stopping at the first, so an
// operator fixing a container environment sees the whole list in one run.
func (r *rawConfig) Resolve() (*Config, error) {
	cfg := &Config{
		ManagementURL:   r.managementURL,
		Hostname:        r.hostname,
		StateDir:        r.stateDir,
		LogLevel:        r.logLevel,
		AllowPublicBind: r.allowPublicBind,
		NoBrowser:       r.noBrowser,
		Check:           r.check,
	}

	setupKey, err := resolveSecret(r.setupKey)
	if err != nil {
		return nil, fmt.Errorf("setup key: %w", err)
	}
	cfg.SetupKey = setupKey

	if len(r.forwards) == 0 {
		return nil, fmt.Errorf("at least one --forward is required (env %s)", FlagNameToEnvVar("forward"))
	}

	var problems []string
	cfg.AllowedHosts, problems = parseAllowedHosts(r.allowedHosts)

	seen := make(map[string]string, len(r.forwards))
	for _, spec := range r.forwards {
		fwd, err := ParseForward(spec)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		// Port 0 means the OS assigns one, so several such forwards do not
		// collide even though they share a spec.
		if prev, dup := seen[fwd.Listen]; dup && !strings.HasSuffix(fwd.Listen, ":0") {
			problems = append(problems, fmt.Sprintf("forward %q: %s is already bound by %q", spec, fwd.Listen, prev))
			continue
		}
		if !cfg.AllowPublicBind && !isLoopback(fwd.Listen) {
			problems = append(problems, fmt.Sprintf(
				"forward %q: %s is not loopback, pass --allow-public-bind (env %s) to expose it",
				spec, fwd.Listen, FlagNameToEnvVar("allow-public-bind")))
			continue
		}
		seen[fwd.Listen] = spec
		fwd.AllowedHosts = cfg.AllowedHosts
		cfg.Forwards = append(cfg.Forwards, fwd)
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %s", strings.Join(problems, "\n  "))
	}

	return cfg, nil
}

// parseAllowedHosts normalizes the names given with --allowed-host and reports
// every entry that is not a plain hostname.
func parseAllowedHosts(raw []string) ([]string, []string) {
	var hosts, problems []string
	for _, entry := range raw {
		name := normalizeHostname(entry)
		if _, err := netip.ParseAddr(name); err == nil {
			problems = append(problems, fmt.Sprintf(
				"allowed host %q: addresses are already accepted on a public listener, list names only", entry))
			continue
		}
		if !hostnamePattern.MatchString(name) {
			problems = append(problems, fmt.Sprintf(
				"allowed host %q: must be a hostname, without scheme, port or wildcard", entry))
			continue
		}
		hosts = append(hosts, name)
	}
	return hosts, problems
}

// normalizeHostname lowercases a name and drops a trailing root dot, so the
// spellings a client may send compare equal.
func normalizeHostname(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ConfigPath returns where the peer identity is persisted, or an empty string
// when the client should keep it in memory only.
func (c *Config) ConfigPath() string {
	if c.StateDir == "" {
		return ""
	}
	return filepath.Join(c.StateDir, "config.json")
}

// StatePath returns where runtime state is persisted, or an empty string when
// no state directory was configured.
func (c *Config) StatePath() string {
	if c.StateDir == "" {
		return ""
	}
	return filepath.Join(c.StateDir, "state.json")
}

// resolveSecret reads a value that may carry a file: prefix naming the file
// that holds it. Whitespace around the file contents is trimmed so a trailing
// newline from the usual tooling does not become part of the secret.
func resolveSecret(value string) (string, error) {
	path, ok := strings.CutPrefix(value, fileScheme)
	if !ok {
		return value, nil
	}
	if path == "" {
		return "", fmt.Errorf("%s prefix with no path", fileScheme)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	// An empty file would otherwise look like no secret at all, silently
	// turning a non-interactive start into a login that waits for a browser.
	secret := strings.TrimSpace(string(content))
	if secret == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}
