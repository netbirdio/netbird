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
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)
		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return fmt.Errorf("init log: %w", err)
		}

		if err := validateEntraFlags(); err != nil {
			return err
		}
		pfxPassword, err := resolvePFXPassword()
		if err != nil {
			return err
		}
		if managementURL == "" {
			return fmt.Errorf("--management-url is required (and must end with /join/entra)")
		}

		// Load profile config so we can reuse the existing WG private key.
		// We deliberately do NOT call UpdateOrCreateConfig here because that
		// would rewrite the entire config. Instead we read, mutate, write.
		pm := profilemanager.NewProfileManager()
		active, err := pm.GetActiveProfile()
		if err != nil {
			return fmt.Errorf("get active profile: %w", err)
		}
		configPath, err := active.FilePath()
		if err != nil {
			return fmt.Errorf("get active profile config path: %w", err)
		}

		// Ensure a config exists with a WG key. Try UpdateOrCreateConfig
		// first (it enforces permissions / ACLs); if that fails on dev boxes
		// where the config dir is under a writable but non-system path, fall
		// back to a direct load-or-create that skips permission enforcement.
		cfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
			ManagementURL: managementURL,
			ConfigPath:    configPath,
		})
		if err != nil {
			log.Warnf("UpdateOrCreateConfig failed (%v) — falling back to direct create (dev/no-ACL path)", err)
			cfg, err = directLoadOrCreateProfileConfig(configPath, managementURL)
			if err != nil {
				return fmt.Errorf("load/create profile config (fallback): %w", err)
			}
		}

		if cfg.EntraEnroll != nil && cfg.EntraEnroll.PeerID != "" {
			cmd.Printf("Profile %q is already Entra-enrolled (peer %s, enrolled %s).\n",
				active.Name, cfg.EntraEnroll.PeerID,
				cfg.EntraEnroll.EnrolledAt.Format(time.RFC3339))
			cmd.Println("Pass --force to re-enrol.")
			if !entraForce {
				return nil
			}
		}

		// Derive the WG public key from the private key stored in the profile.
		privKey, err := wgtypes.ParseKey(cfg.PrivateKey)
		if err != nil {
			return fmt.Errorf("parse profile WG private key: %w", err)
		}
		wgPub := privKey.PublicKey().String()

		// Load the PFX.
		cmd.Printf("Loading device certificate from %s\n", entraPFXPath)
		cert, err := entradevice.LoadPFX(entraPFXPath, pfxPassword)
		if err != nil {
			return fmt.Errorf("load pfx: %w", err)
		}
		deviceID, _ := cert.DeviceID()
		cmd.Printf("Device identity: %s\n", deviceID)

		// Run enrolment.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

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
			// Surface structured server errors with their stable code.
			if structured, ok := err.(*entradevice.Error); ok {
				cmd.PrintErrf("Enrolment rejected: %s (HTTP %d)\n  %s\n",
					structured.Code, structured.HTTPStatus, structured.Message)
				return fmt.Errorf("enrolment failed: %s", structured.Code)
			}
			return fmt.Errorf("enrolment failed: %w", err)
		}

		// Persist: strip /join/entra from the management URL so the next
		// daemon start goes straight to gRPC, and save the state.
		cleanMgmt := strings.TrimSuffix(managementURL, entradevice.EnrolmentPathSuffix)
		cleanURL, err := url.Parse(cleanMgmt)
		if err == nil {
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
			return fmt.Errorf("persist profile config: %w", err)
		}

		cmd.Println()
		cmd.Println("==========  ENROLMENT SUCCESS  ==========")
		cmd.Printf("  Profile                : %s\n", active.Name)
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
		log.Infof("entra-enroll succeeded for peer %s", state.PeerID)
		return nil
	},
}

var entraForce bool

func validateEntraFlags() error {
	switch {
	case entraPFXPath == "":
		return fmt.Errorf("--entra-pfx is required")
	case entraTenantID == "":
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
		"Path to the PKCS#12 (.pfx) file containing the device certificate + private key")
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
