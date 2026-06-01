package server

import (
	"context"
	"fmt"
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
//
// The callback runs in the ticker's own goroutine. Ticker has already
// logged the per-key diff before invoking this hook.
func (s *Server) onMDMPolicyChange(_, _ *mdm.Policy) {
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
	}
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
	return nil
}

// requestedMDMManagedKeys returns the names of MDM-managed keys whose
// corresponding field is set in the SetConfigRequest. Only keys with an
// MDM mapping are considered; other fields are ignored.
func requestedMDMManagedKeys(msg *proto.SetConfigRequest) []string {
	if msg == nil {
		return nil
	}
	var keys []string
	if msg.ManagementUrl != "" {
		keys = append(keys, mdm.KeyManagementURL)
	}
	if msg.OptionalPreSharedKey != nil {
		keys = append(keys, mdm.KeyPreSharedKey)
	}
	if msg.RosenpassEnabled != nil {
		keys = append(keys, mdm.KeyRosenpassEnabled)
	}
	if msg.RosenpassPermissive != nil {
		keys = append(keys, mdm.KeyRosenpassPermissive)
	}
	if msg.DisableAutoConnect != nil {
		keys = append(keys, mdm.KeyDisableAutoConnect)
	}
	if msg.ServerSSHAllowed != nil {
		keys = append(keys, mdm.KeyAllowServerSSH)
	}
	if msg.DisableClientRoutes != nil {
		keys = append(keys, mdm.KeyDisableClientRoutes)
	}
	if msg.DisableServerRoutes != nil {
		keys = append(keys, mdm.KeyDisableServerRoutes)
	}
	if msg.BlockInbound != nil {
		keys = append(keys, mdm.KeyBlockInbound)
	}
	if msg.WireguardPort != nil {
		keys = append(keys, mdm.KeyWireguardPort)
	}
	return keys
}

// rejectMDMManagedFieldConflicts returns a FailedPrecondition gRPC error
// with an MDMManagedFieldsViolation detail when any of the requested keys
// is MDM-enforced, and nil otherwise. The whole request is rejected on
// any conflict; non-conflicting fields in the same request are not
// applied either (no partial apply).
func rejectMDMManagedFieldConflicts(policy *mdm.Policy, requested []string) error {
	if policy.IsEmpty() || len(requested) == 0 {
		return nil
	}
	var conflicts []string
	for _, k := range requested {
		if policy.HasKey(k) {
			conflicts = append(conflicts, k)
		}
	}
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
