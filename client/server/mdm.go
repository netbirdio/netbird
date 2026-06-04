package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// loadMDMPolicy is the indirection used by server handlers to read the
// active MDM policy. Tests override this to inject a fake policy.
var loadMDMPolicy = mdm.LoadPolicy

// onMDMPolicyChange is invoked by the MDM reload ticker every time the
// OS-native managed-config store reports a diff vs the last observation.
//
// Restart sequence:
//   1. Cancel the active engine context (terminates connectWithRetryRuns).
//   2. Wait briefly for that goroutine to exit (giveUpChan is closed on exit).
//   3. Re-resolve Config from disk + MDM policy (Config.apply re-runs
//      applyMDMPolicy with the freshly loaded Policy).
//   4. Spawn a fresh connectWithRetryRuns with the new context and config.
//   5. Broadcast a SystemEvent so any GUI / CLI subscriber (SubscribeEvents
//      RPC) can refresh its cached config view without polling.
//
// The callback runs in the ticker's own goroutine. Ticker has already
// logged the per-key diff before invoking this hook.
func (s *Server) onMDMPolicyChange(_, curr *mdm.Policy) {
	log.Warn("MDM policy changed; restarting engine to apply new configuration")

	s.mutex.Lock()
	cancel := s.actCancel
	giveUpChan := s.clientGiveUpChan
	s.mutex.Unlock()

	if cancel != nil {
		cancel()
	}

	// Wait for previous connectWithRetryRuns to exit so we don't end up
	// with two goroutines fighting over the same status recorder + engine.
	if giveUpChan != nil {
		select {
		case <-giveUpChan:
		case <-time.After(5 * time.Second):
			log.Warn("MDM restart: timeout waiting for previous engine goroutine; proceeding anyway")
		}
	}

	if err := s.restartEngineForMDM(); err != nil {
		log.Errorf("MDM restart failed: %v", err)
		return
	}

	// publishConfigChangedEvent has already fired inside
	// restartEngineForMDM with source="mdm". Here we additionally emit an
	// MDM-specific user-visible toast so the operator knows their IT
	// policy was applied (UserMessage != "" triggers the GUI notifier).
	_ = curr
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"MDM policy applied",
		"NetBird configuration was updated by your IT policy.",
		map[string]string{"source": "mdm", "type": "policy_applied"},
	)
}

// publishConfigChangedEvent broadcasts a SystemEvent informing any active
// SubscribeEvents subscriber (typically the GUI tray) that the daemon's
// effective Config has been replaced and any cached client-side view
// should be refreshed. Callers pass a stable `source` label so the GUI
// can distinguish a startup spawn from a user-triggered Up or an
// MDM-driven restart. Reusing the SYSTEM category keeps the proto enum
// stable; metadata.type="config_changed" routes to the GUI's refresh
// handler. UserMessage is left empty so the system tray does not toast
// for every internal restart; the MDM path emits a separate
// "policy_applied" event (with UserMessage) for that purpose.
func (s *Server) publishConfigChangedEvent(source string) {
	if s.statusRecorder == nil {
		return
	}
	var managed []string
	if s.config != nil {
		managed = s.config.Policy().ManagedKeys()
	}
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		fmt.Sprintf("daemon config changed (source=%s)", source),
		"",
		map[string]string{
			"source":         source,
			"type":           "config_changed",
			"managed_fields": strings.Join(managed, ","),
		},
	)
}

// restartEngineForMDM re-resolves the active profile config (re-running
// applyMDMPolicy via Config.apply) and re-spawns connectWithRetryRuns.
// Mirrors the tail of Server.Start so a runtime MDM change behaves
// identically to a fresh boot under the new policy.
func (s *Server) restartEngineForMDM() error {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return fmt.Errorf("get active profile state: %w", err)
	}
	config, existingConfig, err := s.getConfig(activeProf)
	if err != nil {
		return fmt.Errorf("get active profile config: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.config = config
	s.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)
	s.statusRecorder.UpdateLazyConnection(config.LazyConnectionEnabled)

	state := internal.CtxGetState(s.rootCtx)
	if config.DisableAutoConnect {
		log.Info("MDM restart: DisableAutoConnect=true; staying idle")
		state.Set(internal.StatusIdle)
		s.actCancel = nil
		return nil
	}
	if !existingConfig {
		log.Warn("MDM restart: config absent; not reconnecting")
		state.Set(internal.StatusNeedsLogin)
		s.actCancel = nil
		return nil
	}

	ctx, cancel := context.WithCancel(s.rootCtx)
	s.actCancel = cancel
	s.clientRunning = true
	s.clientRunningChan = make(chan struct{})
	s.clientGiveUpChan = make(chan struct{})
	log.Info("MDM restart: spawning connectWithRetryRuns with re-resolved config")
	go s.connectWithRetryRuns(ctx, config, s.statusRecorder, s.clientRunningChan, s.clientGiveUpChan)
	s.publishConfigChangedEvent("mdm")
	return nil
}

// mdmManagedFieldConflicts returns the names of MDM-managed keys whose
// requested value in the SetConfigRequest differs from the MDM-enforced
// value. A field set to the same value the policy already enforces is
// treated as a no-op echo (the GUI tray sends a full Config snapshot on
// every toggle, so most fields in a typical request match the policy
// exactly and must NOT be flagged as conflicts).
//
// The redacted PreSharedKey sentinel ("**********") that GetConfig
// returns is recognised and treated as no-op so the UI can safely round-
// trip it without tripping the gate.
func mdmManagedFieldConflicts(msg *proto.SetConfigRequest, policy *mdm.Policy) []string {
	if msg == nil || policy.IsEmpty() {
		return nil
	}
	var conflicts []string
	mark := func(key string) { conflicts = append(conflicts, key) }

	if msg.ManagementUrl != "" && policy.HasKey(mdm.KeyManagementURL) {
		if want, ok := policy.GetString(mdm.KeyManagementURL); !ok || want != msg.ManagementUrl {
			mark(mdm.KeyManagementURL)
		}
	}
	if msg.OptionalPreSharedKey != nil && policy.HasKey(mdm.KeyPreSharedKey) {
		// "**********" is the redacted echo from GetConfig — never a real
		// override attempt regardless of what the policy holds.
		if *msg.OptionalPreSharedKey != "**********" {
			if want, ok := policy.GetString(mdm.KeyPreSharedKey); !ok || want != *msg.OptionalPreSharedKey {
				mark(mdm.KeyPreSharedKey)
			}
		}
	}
	checkBool := func(key string, p *bool) {
		if p == nil || !policy.HasKey(key) {
			return
		}
		if want, ok := policy.GetBool(key); !ok || want != *p {
			mark(key)
		}
	}
	checkBool(mdm.KeyRosenpassEnabled, msg.RosenpassEnabled)
	checkBool(mdm.KeyRosenpassPermissive, msg.RosenpassPermissive)
	checkBool(mdm.KeyDisableAutoConnect, msg.DisableAutoConnect)
	checkBool(mdm.KeyAllowServerSSH, msg.ServerSSHAllowed)
	checkBool(mdm.KeyDisableClientRoutes, msg.DisableClientRoutes)
	checkBool(mdm.KeyDisableServerRoutes, msg.DisableServerRoutes)
	checkBool(mdm.KeyBlockInbound, msg.BlockInbound)

	if msg.WireguardPort != nil && policy.HasKey(mdm.KeyWireguardPort) {
		if want, ok := policy.GetInt(mdm.KeyWireguardPort); !ok || want != *msg.WireguardPort {
			mark(mdm.KeyWireguardPort)
		}
	}
	return conflicts
}

// setConfigRequestHasConfigOverrides reports whether the SetConfigRequest
// carries ANY field that would actually mutate the persisted config. The
// CLI builds the request unconditionally on every `netbird up` (see
// setupSetConfigReq in cmd/up.go), so a plain `netbird up` results in a
// SetConfig call with every field at its zero value; the gate must skip
// such no-op invocations or it would always fire even when the user did
// not pass any --flag.
func setConfigRequestHasConfigOverrides(msg *proto.SetConfigRequest) bool {
	if msg == nil {
		return false
	}
	return msg.ManagementUrl != "" ||
		msg.AdminURL != "" ||
		msg.OptionalPreSharedKey != nil ||
		len(msg.CustomDNSAddress) > 0 ||
		len(msg.NatExternalIPs) > 0 || msg.CleanNATExternalIPs ||
		len(msg.ExtraIFaceBlacklist) > 0 ||
		len(msg.DnsLabels) > 0 || msg.CleanDNSLabels ||
		msg.DnsRouteInterval != nil ||
		msg.RosenpassEnabled != nil ||
		msg.RosenpassPermissive != nil ||
		msg.InterfaceName != nil ||
		msg.WireguardPort != nil ||
		msg.Mtu != nil ||
		msg.DisableAutoConnect != nil ||
		msg.ServerSSHAllowed != nil ||
		msg.NetworkMonitor != nil ||
		msg.DisableClientRoutes != nil ||
		msg.DisableServerRoutes != nil ||
		msg.DisableDns != nil ||
		msg.DisableFirewall != nil ||
		msg.BlockLanAccess != nil ||
		msg.DisableNotifications != nil ||
		msg.LazyConnectionEnabled != nil ||
		msg.BlockInbound != nil ||
		msg.DisableIpv6 != nil ||
		msg.EnableSSHRoot != nil ||
		msg.EnableSSHSFTP != nil ||
		msg.EnableSSHLocalPortForwarding != nil ||
		msg.EnableSSHRemotePortForwarding != nil ||
		msg.DisableSSHAuth != nil ||
		msg.SshJWTCacheTTL != nil
}

// loginRequestHasConfigOverrides reports whether the LoginRequest
// carries ANY field that would mutate persisted daemon configuration
// (as opposed to pure-auth fields like setupKey, hostname, hint,
// profileName, username). Used by the Login handler to decide whether
// the `--disable-update-settings` / MDM gates must run: a re-auth that
// changes nothing about the configuration is always allowed.
func loginRequestHasConfigOverrides(msg *proto.LoginRequest) bool {
	if msg == nil {
		return false
	}
	return msg.ManagementUrl != "" ||
		msg.AdminURL != "" ||
		msg.PreSharedKey != "" ||
		msg.OptionalPreSharedKey != nil ||
		len(msg.CustomDNSAddress) > 0 ||
		len(msg.NatExternalIPs) > 0 || msg.CleanNATExternalIPs ||
		msg.RosenpassEnabled != nil ||
		msg.InterfaceName != nil ||
		msg.WireguardPort != nil ||
		msg.DisableAutoConnect != nil ||
		msg.ServerSSHAllowed != nil ||
		msg.RosenpassPermissive != nil ||
		len(msg.ExtraIFaceBlacklist) > 0 ||
		msg.NetworkMonitor != nil ||
		msg.DnsRouteInterval != nil ||
		msg.DisableClientRoutes != nil ||
		msg.DisableServerRoutes != nil ||
		msg.DisableDns != nil ||
		msg.DisableFirewall != nil ||
		msg.BlockLanAccess != nil ||
		msg.DisableNotifications != nil ||
		len(msg.DnsLabels) > 0 || msg.CleanDNSLabels ||
		msg.LazyConnectionEnabled != nil ||
		msg.BlockInbound != nil
}

// loginRequestMDMConflicts mirrors mdmManagedFieldConflicts but for the
// LoginRequest surface. Same value-aware semantics: a field set to the
// MDM-enforced value is a no-op echo, not a conflict; only a divergent
// value is flagged. PSK has two proto fields (PreSharedKey deprecated
// and OptionalPreSharedKey current); both routes are checked, and the
// "**********" redaction sentinel is accepted as a no-op.
func loginRequestMDMConflicts(msg *proto.LoginRequest, policy *mdm.Policy) []string {
	if msg == nil || policy.IsEmpty() {
		return nil
	}
	var conflicts []string
	mark := func(key string) { conflicts = append(conflicts, key) }

	if msg.ManagementUrl != "" && policy.HasKey(mdm.KeyManagementURL) {
		if want, ok := policy.GetString(mdm.KeyManagementURL); !ok || want != msg.ManagementUrl {
			mark(mdm.KeyManagementURL)
		}
	}

	// PSK: PreSharedKey (deprecated) and OptionalPreSharedKey are both
	// accepted by Login; either trips the gate if it diverges from the
	// MDM-enforced PSK.
	if policy.HasKey(mdm.KeyPreSharedKey) {
		psk := ""
		set := false
		if msg.OptionalPreSharedKey != nil {
			psk = *msg.OptionalPreSharedKey
			set = true
		} else if msg.PreSharedKey != "" {
			psk = msg.PreSharedKey
			set = true
		}
		if set && psk != "**********" {
			if want, ok := policy.GetString(mdm.KeyPreSharedKey); !ok || want != psk {
				mark(mdm.KeyPreSharedKey)
			}
		}
	}

	checkBool := func(key string, p *bool) {
		if p == nil || !policy.HasKey(key) {
			return
		}
		if want, ok := policy.GetBool(key); !ok || want != *p {
			mark(key)
		}
	}
	checkBool(mdm.KeyRosenpassEnabled, msg.RosenpassEnabled)
	checkBool(mdm.KeyRosenpassPermissive, msg.RosenpassPermissive)
	checkBool(mdm.KeyDisableAutoConnect, msg.DisableAutoConnect)
	checkBool(mdm.KeyAllowServerSSH, msg.ServerSSHAllowed)
	checkBool(mdm.KeyDisableClientRoutes, msg.DisableClientRoutes)
	checkBool(mdm.KeyDisableServerRoutes, msg.DisableServerRoutes)
	checkBool(mdm.KeyBlockInbound, msg.BlockInbound)

	if msg.WireguardPort != nil && policy.HasKey(mdm.KeyWireguardPort) {
		if want, ok := policy.GetInt(mdm.KeyWireguardPort); !ok || want != *msg.WireguardPort {
			mark(mdm.KeyWireguardPort)
		}
	}
	return conflicts
}

// rejectMDMManagedFieldConflicts returns a FailedPrecondition gRPC error
// with an MDMManagedFieldsViolation detail when any of the requested
// fields tries to change an MDM-enforced value to something else, and
// nil otherwise. The whole request is rejected on any conflict; non-
// conflicting fields in the same request are not applied either (no
// partial apply).
func rejectMDMManagedFieldConflicts(policy *mdm.Policy, conflicts []string) error {
	if len(conflicts) == 0 {
		return nil
	}
	_ = policy
	log.Warnf("MDM rejected request: tried to modify %d managed key(s): %v",
		len(conflicts), conflicts)
	st := gstatus.New(
		codes.FailedPrecondition,
		fmt.Sprintf("fields managed by MDM cannot be modified: %v", conflicts),
	)
	detailed, err := st.WithDetails(&proto.MDMManagedFieldsViolation{Fields: conflicts})
	if err != nil {
		// Detail attachment is best-effort; fall back to the plain status
		// so the caller still gets a usable FailedPrecondition.
		return st.Err()
	}
	return detailed.Err()
}
