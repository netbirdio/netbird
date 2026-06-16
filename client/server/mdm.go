package server

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// preSharedKeyRedactedSentinel is the value GetConfig returns in place
// of an actual PSK, so a UI that round-trips the field back to the
// daemon (via SetConfig / Login) can be distinguished from a deliberate
// override. Any incoming PSK that equals this sentinel is treated as
// a no-op echo, never as a conflict with the policy.
const preSharedKeyRedactedSentinel = "**********"

// loadMDMPolicy is the indirection used by server handlers to read the
// active MDM policy. Tests override this to inject a fake policy.
var loadMDMPolicy = mdm.LoadPolicy

// conflictCheck is a value-aware comparison between a single field in
// the incoming request and the corresponding MDM-enforced value. It
// runs only when the field was actually set in the request (presence
// already filtered upstream); ok=true reports the policy value, ok=false
// means the policy is silent on the key — both are treated as conflicts
// to be safe (an MDM key declared as managed must hold a value).
type conflictCheck struct {
	key   string
	check func(*mdm.Policy) (match bool)
}

// onMDMPolicyChange is invoked by the MDM reload ticker every time the
// OS-native managed-config store reports a diff vs the last observation.
//
// Restart sequence:
//  1. Cancel the active engine context (terminates connectWithRetryRuns).
//  2. Wait briefly for that goroutine to exit (giveUpChan is closed on exit).
//  3. Re-resolve Config from disk + MDM policy (Config.apply re-runs
//     applyMDMPolicy with the freshly loaded Policy).
//  4. Spawn a fresh connectWithRetryRuns with the new context and config.
//  5. Broadcast a SystemEvent so any GUI / CLI subscriber (SubscribeEvents
//     RPC) can refresh its cached config view without polling.
//
// The callback runs in the ticker's own goroutine. Ticker has already
// logged the per-key diff before invoking this hook.
func (s *Server) onMDMPolicyChange(_, _ *mdm.Policy) error {
	log.Warn("MDM policy changed; restarting engine to apply new configuration")

	// Hold s.mutex for the entire restart sequence (cancel + quiescence
	// wait + re-spawn). Any concurrent Up/Down/Status arriving while
	// MDM is restarting blocks on the Lock until we are done — they
	// then observe the post-restart state coherently. This is safe
	// because the connectWithRetryRuns goroutine no longer acquires
	// s.mutex in its defer (intent vs. goroutine-alive concerns are
	// fully separated; see the connectionGoroutineRunning helper).
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.clientRunning {
		// The client is not running, so there's no engine to restart.
		return nil
	}
	if s.actCancel != nil {
		s.actCancel()
	}

	// Wait for previous connectWithRetryRuns to exit so we don't end up
	// with two goroutines fighting over the same status recorder + engine.
	// The teardown engages a fan-out of engine goroutines (peer workers,
	// signal handler, route manager, ...). close(clientGiveUpChan)
	// happens in the function-scope defer of connectWithRetryRuns, on
	// every exit path (ctx cancel, backoff exhausted, panic) — see the
	// defer in server.go.
	if s.clientGiveUpChan != nil {
		select {
		case <-s.clientGiveUpChan:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("failed to restart the engine due to timeout")
		}
	}

	if err := s.restartEngineForMDMLocked(); err != nil {
		log.Errorf("MDM restart failed: %v", err)
		return err
	}

	// publishConfigChangedEvent has already fired inside
	// restartEngineForMDMLocked with source="mdm". Emit an MDM-specific
	// user-visible toast so the operator knows their IT policy was
	// applied (UserMessage != "" triggers the GUI notifier).
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"MDM policy applied",
		"NetBird configuration was updated by your IT policy.",
		map[string]string{
			proto.MetadataSourceKey: proto.MetadataSourceMDM,
			proto.MetadataTypeKey:   proto.MetadataTypePolicyApplied,
		},
	)
	return nil
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
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		fmt.Sprintf("daemon config changed (source=%s)", source),
		"",
		map[string]string{
			proto.MetadataSourceKey: source,
			proto.MetadataTypeKey:   proto.MetadataTypeConfigChanged,
		},
	)
}

// restartEngineForMDMLocked re-resolves the active profile config
// (re-running applyMDMPolicy via Config.apply) and re-spawns
// connectWithRetryRuns. Mirrors the tail of Server.Start so a runtime
// MDM change behaves identically to a fresh boot under the new policy.
//
// MUST be called with s.mutex held — onMDMPolicyChange holds the lock
// for the entire restart sequence (cancel + quiescence wait + re-spawn)
// so concurrent Up/Down/Status RPCs observe a coherent post-restart
// state.
func (s *Server) restartEngineForMDMLocked() error {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return fmt.Errorf("get active profile state: %w", err)
	}
	config, _, err := s.getConfig(activeProf)
	if err != nil {
		return fmt.Errorf("get active profile config: %w", err)
	}

	s.config = config
	s.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)
	s.statusRecorder.UpdateLazyConnection(config.LazyConnectionEnabled)

	ctx, cancel := context.WithCancel(s.rootCtx)
	s.actCancel = cancel
	s.clientRunning = true
	s.clientRunningChan = make(chan struct{})
	s.clientGiveUpChan = make(chan struct{})
	log.Info("MDM restart: spawning connectWithRetryRuns with re-resolved config")
	go s.connectWithRetryRuns(ctx, config, s.statusRecorder, s.clientRunningChan, s.clientGiveUpChan)
	s.publishConfigChangedEvent(proto.MetadataSourceMDM)
	return nil
}

// conflictBool builds a conflictCheck for a boolean MDM key. If p is nil
// the field is treated as matching (no override requested); otherwise the
// check returns true only when the policy contains the key and its
// boolean value equals *p.
func conflictBool(key string, p *bool) conflictCheck {
	return conflictCheck{
		key: key,
		check: func(pol *mdm.Policy) bool {
			if p == nil {
				return true // absent → match by definition
			}
			want, ok := pol.GetBool(key)
			return ok && want == *p
		},
	}
}

// conflictString builds a conflictCheck for a string MDM key. An empty
// `got` is treated as "field not set" (no override requested); otherwise
// the check returns true only when the policy contains the key and its
// value equals got.
func conflictString(key, got string) conflictCheck {
	return conflictCheck{
		key: key,
		check: func(pol *mdm.Policy) bool {
			if got == "" {
				return true
			}
			want, ok := pol.GetString(key)
			return ok && want == got
		},
	}
}

// conflictInt64 builds a conflictCheck for an integer MDM key. If p is
// nil the field is treated as matching; otherwise the check returns
// true only when the policy contains the key and its int value equals *p.
func conflictInt64(key string, p *int64) conflictCheck {
	return conflictCheck{
		key: key,
		check: func(pol *mdm.Policy) bool {
			if p == nil {
				return true
			}
			want, ok := pol.GetInt(key)
			return ok && want == *p
		},
	}
}

// resolveConflicts walks the per-field checks against the active MDM
// policy and returns the names of keys whose requested value diverges
// from the policy-enforced value. Keys not present in the policy are
// skipped silently (the gate fires only for keys the admin has
// actually pushed). Returns nil for an empty policy.
func resolveConflicts(policy *mdm.Policy, checks []conflictCheck) []string {
	if policy.IsEmpty() {
		return nil
	}
	var conflicts []string
	for _, c := range checks {
		if !policy.HasKey(c.key) {
			continue
		}
		if !c.check(policy) {
			conflicts = append(conflicts, c.key)
		}
	}
	return conflicts
}

// mdmManagedFieldConflicts returns the names of MDM-managed keys whose
// requested value in the SetConfigRequest differs from the MDM-enforced
// value. A field set to the same value the policy already enforces is
// treated as a no-op echo (the GUI tray sends a full Config snapshot on
// every toggle, so most fields in a typical request match the policy
// exactly and must NOT be flagged as conflicts). The redacted PSK
// sentinel ("**********") returned by GetConfig is recognised and
// treated as no-op so the UI can safely round-trip it.
func mdmManagedFieldConflicts(msg *proto.SetConfigRequest, policy *mdm.Policy) []string {
	if msg == nil {
		return nil
	}

	// PSK round-trip echo: collapse the sentinel to empty so the
	// shared check treats it as "field not set".
	pskGot := ""
	if msg.OptionalPreSharedKey != nil && *msg.OptionalPreSharedKey != preSharedKeyRedactedSentinel {
		pskGot = *msg.OptionalPreSharedKey
	}

	return resolveConflicts(policy, []conflictCheck{
		conflictString(mdm.KeyManagementURL, msg.ManagementUrl),
		conflictString(mdm.KeyPreSharedKey, pskGot),
		conflictBool(mdm.KeyRosenpassEnabled, msg.RosenpassEnabled),
		conflictBool(mdm.KeyRosenpassPermissive, msg.RosenpassPermissive),
		conflictBool(mdm.KeyDisableAutoConnect, msg.DisableAutoConnect),
		conflictBool(mdm.KeyAllowServerSSH, msg.ServerSSHAllowed),
		conflictBool(mdm.KeyDisableClientRoutes, msg.DisableClientRoutes),
		conflictBool(mdm.KeyDisableServerRoutes, msg.DisableServerRoutes),
		conflictBool(mdm.KeyBlockInbound, msg.BlockInbound),
		conflictInt64(mdm.KeyWireguardPort, msg.WireguardPort),
	})
}

// setConfigRequestHasConfigOverrides reports whether the SetConfigRequest
// carries ANY field that would actually mutate the persisted config.
// The CLI builds a SetConfigRequest unconditionally on every
// `netbird up` (see setupSetConfigReq in cmd/up.go) — a plain
// `netbird up` produces a request with every field at its zero value;
// the gate must skip such no-op invocations or it would always fire
// even when the user did not pass any --flag. Returns false on a nil
// msg; true when any management/admin URL, PSK, DNS/NAT list+clean
// flag, interface/port/MTU, or any optional bool/duration field is set.
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
		msg.PreSharedKey != "" || //nolint:staticcheck // SA1019: legacy proto field still accepted by Login
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
// value is flagged. PSK has two proto fields — PreSharedKey (deprecated)
// and OptionalPreSharedKey (current); either route trips the gate if it
// diverges from the MDM-enforced PSK. OptionalPreSharedKey wins when
// both are set; the redaction sentinel ("**********") is accepted as
// a no-op echo.
func loginRequestMDMConflicts(msg *proto.LoginRequest, policy *mdm.Policy) []string {
	if msg == nil {
		return nil
	}

	// Collapse the two PSK fields + the redaction sentinel down to a
	// single "got" string the shared check can compare against the
	// policy: OptionalPreSharedKey wins if set; PreSharedKey (deprecated)
	// is the fallback; sentinel echo is treated as "field not set".
	pskGot := ""
	if msg.OptionalPreSharedKey != nil {
		pskGot = *msg.OptionalPreSharedKey
	} else if msg.PreSharedKey != "" { //nolint:staticcheck // SA1019: legacy proto field still accepted by Login
		pskGot = msg.PreSharedKey //nolint:staticcheck // SA1019
	}
	if pskGot == preSharedKeyRedactedSentinel {
		pskGot = ""
	}

	return resolveConflicts(policy, []conflictCheck{
		conflictString(mdm.KeyManagementURL, msg.ManagementUrl),
		conflictString(mdm.KeyPreSharedKey, pskGot),
		conflictBool(mdm.KeyRosenpassEnabled, msg.RosenpassEnabled),
		conflictBool(mdm.KeyRosenpassPermissive, msg.RosenpassPermissive),
		conflictBool(mdm.KeyDisableAutoConnect, msg.DisableAutoConnect),
		conflictBool(mdm.KeyAllowServerSSH, msg.ServerSSHAllowed),
		conflictBool(mdm.KeyDisableClientRoutes, msg.DisableClientRoutes),
		conflictBool(mdm.KeyDisableServerRoutes, msg.DisableServerRoutes),
		conflictBool(mdm.KeyBlockInbound, msg.BlockInbound),
		conflictInt64(mdm.KeyWireguardPort, msg.WireguardPort),
	})
}

// rejectMDMManagedFieldConflicts returns a FailedPrecondition gRPC error
// with an MDMManagedFieldsViolation detail when any of the requested
// fields tries to change an MDM-enforced value to something else, and
// nil otherwise. The whole request is rejected on any conflict; non-
// conflicting fields in the same request are not applied either (no
// partial apply).
func rejectMDMManagedFieldConflicts(conflicts []string) error {
	if len(conflicts) == 0 {
		return nil
	}
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
