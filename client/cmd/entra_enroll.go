package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/enroll/entradevice"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util"
)

// Local flags for the subcommand (kept here rather than on the root so they
// don't clutter every other netbird subcommand).
// NOTE: Windows cert-store + TPM-backed CNG signing is the intended
// production path (see docs/ENTRA_DEVICE_AUTH.md "Future work" section).
// It needs either CGO + mingw-w64 in the build chain (smimesign/certstore)
// or a hand-rolled pure-Go wrapper over ncrypt.dll. Neither is in this
// commit; PFX is the currently-supported cert source.
var (
	entraPFXPath     string
	entraPFXPassword string
	entraPFXPassEnv  string
	entraTenantID    string
	entraHostname    string
)

// entraEnrollCmd drives a one-shot Entra device enrolment against the
// management server's /join/entra endpoints and persists the resulting state
// into the active profile's config file.
var entraEnrollCmd = &cobra.Command{
	Use:   "entra-enroll",
	Short: "Enrol this device via the Entra/Intune device-auth endpoint",
	Long: `Run the Entra device authentication enrolment flow against a NetBird
management server.

This fetches a challenge nonce from /join/entra/challenge, signs it with the
private key in the supplied PFX certificate, POSTs /join/entra/enroll, and
saves the resulting state (peer id, tenant, auto-groups) into the active
profile's config file.

After successful enrolment the peer is already registered on the server by
its WireGuard public key, so subsequent 'netbird up' calls on the same
profile proceed with the normal gRPC Login without any further user
interaction.

Example:

  netbird entra-enroll \
    --management-url https://mgmt.example.dk/join/entra \
    --entra-tenant   5a7a81b2-99cc-45fc-b6d1-cd01ba176c26 \
    --entra-pfx      C:\ProgramData\NetBird\device.pfx \
    --entra-pfx-password-env NB_ENTRA_PFX_PASSWORD`,
	RunE: runEntraEnroll,
}

// runEntraEnroll is the entry point invoked by cobra. Kept as a thin
// orchestrator that delegates to phase-specific helpers so each piece is
// reviewable in isolation and SonarCloud's complexity / length thresholds
// are respected.
func runEntraEnroll(cmd *cobra.Command, _ []string) error {
	SetFlagsFromEnvVars(rootCmd)
	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		return fmt.Errorf("init log: %w", err)
	}
	pfxPassword, err := preflightEntraEnroll()
	if err != nil {
		return err
	}

	active, configPath, cfg, err := loadOrCreateProfileConfig()
	if err != nil {
		return err
	}
	if ok, err := maybeSkipAlreadyEnrolled(cmd, active.Name, cfg); ok {
		return err
	}

	wgPub, err := derivedWGPubKey(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	state, err := performEntraEnrolment(ctx, cmd, pfxPassword, wgPub)
	if err != nil {
		return err
	}

	cleanMgmt, err := persistEnrolmentState(ctx, cfg, configPath, state)
	if err != nil {
		return err
	}
	printEnrolmentSuccess(cmd, active.Name, state, cleanMgmt)
	log.Infof("entra-enroll succeeded for peer %s", state.PeerID)
	return nil
}

// preflightEntraEnroll validates flags + resolves the PFX password + checks
// that --management-url was supplied.
func preflightEntraEnroll() (string, error) {
	if err := validateEntraFlags(); err != nil {
		return "", err
	}
	if managementURL == "" {
		return "", fmt.Errorf("--management-url is required (and must end with /join/entra)")
	}
	return resolvePFXPassword()
}

// loadOrCreateProfileConfig returns the active profile, its config path, and
// a loaded Config. It first tries the ACL-enforcing UpdateOrCreateConfig and
// falls back to a plain WriteJson path for dev boxes where the config dir is
// under a writable but non-system location.
func loadOrCreateProfileConfig() (*profilemanager.Profile, string, *profilemanager.Config, error) {
	pm := profilemanager.NewProfileManager()
	active, err := pm.GetActiveProfile()
	if err != nil {
		return nil, "", nil, fmt.Errorf("get active profile: %w", err)
	}
	configPath, err := active.FilePath()
	if err != nil {
		return nil, "", nil, fmt.Errorf("get active profile config path: %w", err)
	}
	cfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ManagementURL: managementURL,
		ConfigPath:    configPath,
	})
	if err != nil {
		log.Warnf("UpdateOrCreateConfig failed (%v) — falling back to direct create (dev/no-ACL path)", err)
		cfg, err = directLoadOrCreateProfileConfig(configPath, managementURL)
		if err != nil {
			return nil, "", nil, fmt.Errorf("load/create profile config (fallback): %w", err)
		}
	}
	return active, configPath, cfg, nil
}

// maybeSkipAlreadyEnrolled reports whether the active profile already carries
// a persisted EntraEnrollState. Returns (true, nil) when the caller should
// exit cleanly, (false, nil) when enrolment should proceed (either no prior
// state, or --force was supplied).
func maybeSkipAlreadyEnrolled(cmd *cobra.Command, profileName string, cfg *profilemanager.Config) (bool, error) {
	if cfg.EntraEnroll == nil || cfg.EntraEnroll.PeerID == "" {
		return false, nil
	}
	cmd.Printf("Profile %q is already Entra-enrolled (peer %s, enrolled %s).\n",
		profileName, cfg.EntraEnroll.PeerID,
		cfg.EntraEnroll.EnrolledAt.Format(time.RFC3339))
	cmd.Println("Pass --force to re-enrol.")
	if !entraForce {
		return true, nil
	}
	return false, nil
}

// derivedWGPubKey returns the base64 WireGuard public key derived from the
// profile's stored private key.
func derivedWGPubKey(cfg *profilemanager.Config) (string, error) {
	privKey, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse profile WG private key: %w", err)
	}
	return privKey.PublicKey().String(), nil
}

// performEntraEnrolment loads the PFX, constructs the Enroller, and runs the
// HTTP round-trip. Structured server errors surface their stable code.
func performEntraEnrolment(ctx context.Context, cmd *cobra.Command, pfxPassword, wgPub string) (*entradevice.EntraEnrollState, error) {
	cmd.Printf("Loading device certificate from %s\n", entraPFXPath)
	cert, err := entradevice.LoadPFX(entraPFXPath, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("load pfx: %w", err)
	}
	deviceID, _ := cert.DeviceID()
	cmd.Printf("Device identity: %s\n", deviceID)

	en := &entradevice.Enroller{
		BaseURL:  strings.TrimSuffix(managementURL, entradevice.EnrolmentPathSuffix),
		Cert:     cert,
		TenantID: entraTenantID,
		WGPubKey: wgPub,
		Hostname: entraHostname,
	}
	cmd.Printf("Enrolling against %s (tenant %s)\n", en.BaseURL+entradevice.EnrolmentPathSuffix, entraTenantID)

	state, err := en.Enrol(ctx)
	if err != nil {
		if structured, ok := err.(*entradevice.Error); ok {
			cmd.PrintErrf("Enrolment rejected: %s (HTTP %d)\n  %s\n",
				structured.Code, structured.HTTPStatus, structured.Message)
			return nil, fmt.Errorf("enrolment failed: %s", structured.Code)
		}
		return nil, fmt.Errorf("enrolment failed: %w", err)
	}
	return state, nil
}

// persistEnrolmentState strips /join/entra from the saved ManagementURL,
// copies the response fields into the profile config, and writes it out.
func persistEnrolmentState(ctx context.Context, cfg *profilemanager.Config, configPath string, state *entradevice.EntraEnrollState) (string, error) {
	cleanMgmt := strings.TrimSuffix(managementURL, entradevice.EnrolmentPathSuffix)
	if cleanURL, err := url.Parse(cleanMgmt); err == nil {
		cfg.ManagementURL = cleanURL
	}
	cfg.EntraEnroll = &profilemanager.EntraEnrollState{
		EntraDeviceID:      state.EntraDeviceID,
		TenantID:           state.TenantID,
		PeerID:             state.PeerID,
		EnrolledAt:         state.EnrolledAt,
		EnrolledViaURL:     state.EnrolledViaURL,
		ResolutionMode:     state.ResolutionMode,
		ResolvedAutoGroups: state.ResolvedAutoGroups,
		MatchedMappingIDs:  state.MatchedMappingIDs,
	}
	if err := util.WriteJson(ctx, configPath, cfg); err != nil {
		return "", fmt.Errorf("persist profile config: %w", err)
	}
	return cleanMgmt, nil
}

// printEnrolmentSuccess writes the human-readable success banner.
func printEnrolmentSuccess(cmd *cobra.Command, profileName string, state *entradevice.EntraEnrollState, cleanMgmt string) {
	cmd.Println()
	cmd.Println("==========  ENROLMENT SUCCESS  ==========")
	cmd.Printf("  Profile                : %s\n", profileName)
	cmd.Printf("  Peer ID                : %s\n", state.PeerID)
	cmd.Printf("  Entra device id        : %s\n", state.EntraDeviceID)
	cmd.Printf("  Tenant id              : %s\n", state.TenantID)
	cmd.Printf("  Resolution mode        : %s\n", state.ResolutionMode)
	cmd.Printf("  Matched mapping(s)     : %v\n", state.MatchedMappingIDs)
	cmd.Printf("  Resolved auto-groups   : %v\n", state.ResolvedAutoGroups)
	cmd.Printf("  Management URL (saved) : %s\n", cleanMgmt)
	cmd.Println()
	cmd.Println("  Run 'netbird up' to bring the peer online.")
	cmd.Println("=========================================")
}

var entraForce bool

func validateEntraFlags() error {
	if entraPFXPath == "" {
		return fmt.Errorf("--entra-pfx is required")
	}
	if entraTenantID == "" {
		return fmt.Errorf("--entra-tenant is required")
	}
	return nil
}

func resolvePFXPassword() (string, error) {
	if entraPFXPassword != "" {
		return entraPFXPassword, nil
	}
	if entraPFXPassEnv != "" {
		v := os.Getenv(entraPFXPassEnv)
		if v == "" {
			return "", fmt.Errorf("--entra-pfx-password-env %s is unset or empty", entraPFXPassEnv)
		}
		return v, nil
	}
	// Unprotected PFX — uncommon, but allowed.
	return "", nil
}

// directLoadOrCreateProfileConfig bypasses util.WriteJsonWithRestrictedPermission
// (which fails on dev boxes without admin) and writes the config file with plain
// JSON + restrictive mode bits. Only used as a fallback when the normal path
// returns an ACL error.
func directLoadOrCreateProfileConfig(configPath, managementURL string) (*profilemanager.Config, error) {
	if _, err := os.Stat(configPath); err == nil {
		cfg := &profilemanager.Config{}
		if _, err := util.ReadJson(configPath, cfg); err != nil {
			return nil, fmt.Errorf("read existing config: %w", err)
		}
		return cfg, nil
	}

	// Use in-memory constructor to get a pristine Config with WG/SSH keys,
	// then write it via the non-ACL-enforcing util.WriteJson.
	cfg, err := profilemanager.CreateInMemoryConfig(profilemanager.ConfigInput{
		ManagementURL: managementURL,
		ConfigPath:    configPath,
	})
	if err != nil {
		return nil, fmt.Errorf("create in-memory config: %w", err)
	}
	if err := os.MkdirAll(filepathDir(configPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", configPath, err)
	}
	if err := util.WriteJson(context.Background(), configPath, cfg); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	return cfg, nil
}

func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func init() {
	entraEnrollCmd.Flags().StringVar(&entraPFXPath, "entra-pfx", "",
		"Path to the PKCS#12 (.pfx) file containing the device certificate + private key. "+
			"Deploy this via an Intune PKCS Certificate profile (supports Windows + macOS). "+
			"Cert-store + TPM-backed signing is a planned follow-up.")
	entraEnrollCmd.Flags().StringVar(&entraPFXPassword, "entra-pfx-password", "",
		"Password for the PFX file (prefer --entra-pfx-password-env to avoid leaking it via ps/history)")
	entraEnrollCmd.Flags().StringVar(&entraPFXPassEnv, "entra-pfx-password-env", "NB_ENTRA_PFX_PASSWORD",
		"Name of the environment variable holding the PFX password")
	entraEnrollCmd.Flags().StringVar(&entraTenantID, "entra-tenant", "",
		"Entra tenant id the management server has an integration configured for")
	entraEnrollCmd.Flags().StringVar(&entraHostname, "entra-hostname", "",
		"Hostname to present to the server (defaults to 'entra-<device-id>')")
	entraEnrollCmd.Flags().BoolVar(&entraForce, "force", false,
		"Re-enrol even if this profile already has a persisted EntraEnrollState")
}
