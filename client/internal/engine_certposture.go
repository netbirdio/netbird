package internal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/certproof"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

const (
	// certContextPollInterval is how often the engine checks whether the user who can
	// answer certificate challenges has changed, such as a login after an autostart.
	certContextPollInterval = time.Minute
	// certRetryInterval is how long after a collection that proved nothing it is tried
	// again with the same user, for stores that come up late: a keychain unlocked after
	// login, or a TPM resource manager started after the daemon.
	certRetryInterval = 5 * time.Minute
)

// errSystemInfoTimeout reports that gathering the system info for a meta sync timed out,
// so the sync was skipped rather than holding syncMsgMux on a stuck system call.
var errSystemInfoTimeout = errors.New("system info gathering timed out")

// certPostureState remembers what the last certificate proof collection saw, so the
// engine can collect again when it went stale and tell the user when proofs go missing.
type certPostureState struct {
	mu          sync.Mutex
	attempted   bool
	attemptedAt time.Time
	userContext string
	proven      bool
}

// record stores the outcome of a collection and reports whether it changed from proven
// to unproven or back. The first collection only counts as a change when it proved nothing.
func (s *certPostureState) record(userContext string, proven bool, now time.Time) (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed = (s.attempted && s.proven != proven) || (!s.attempted && !proven)
	s.attempted = true
	s.attemptedAt = now
	s.userContext = userContext
	s.proven = proven
	return changed
}

// stale reports whether the last collection no longer reflects what the device can
// prove: the user who can answer has changed, or nothing was proven and the retry
// interval has passed. Before the first collection the sync itself collects.
func (s *certPostureState) stale(userContext string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.attempted {
		return false
	}
	if userContext != s.userContext {
		return true
	}
	return !s.proven && now.Sub(s.attemptedAt) >= certRetryInterval
}

// attachCertificateProofs answers the certificate challenges in checks with the
// certificates reachable on this device, signing each challenge nonce for our peer key.
// Collection is bounded in time because callers hold the sync loop while it runs.
func (e *Engine) attachCertificateProofs(info *system.Info, checks []*mgmProto.Checks) {
	if !certproof.HasChallenges(checks) {
		info.CertificateProofs = nil
		return
	}
	userContext := certproof.UserContext(e.config.CertStore)
	peerKey := e.config.WgPrivateKey.PublicKey()
	info.CertificateProofs = e.certProofs.Collect(e.ctx, checks, peerKey[:], e.config.CertStore)

	proven := len(info.CertificateProofs) > 0
	if e.certState.record(userContext, proven, time.Now()) {
		e.publishCertificatePostureEvent(proven)
	}
}

// publishCertificatePostureEvent tells the user when the device stops proving any
// certificate, which management treats as failing every certificate posture check, and
// when it proves one again. Without it the loss of access would have no visible cause.
func (e *Engine) publishCertificatePostureEvent(proven bool) {
	if e.statusRecorder == nil {
		return
	}
	if proven {
		e.statusRecorder.PublishEvent(cProto.SystemEvent_INFO, cProto.SystemEvent_SYSTEM,
			"certificate posture: a certificate is proven again",
			"A certificate required by your organization's device policy is available again.", nil)
		return
	}
	e.statusRecorder.PublishEvent(cProto.SystemEvent_WARNING, cProto.SystemEvent_SYSTEM,
		"certificate posture: no certificate could be proven",
		"NetBird could not use a certificate required by your organization's device policy. "+
			"Access to some resources may be blocked until one is available.", nil)
}

// watchCertificatePosture collects certificate proofs again when the last collection
// went stale, until ctx is done. Proofs are otherwise only collected when the checks
// change or the sync stream reconnects, so a daemon started before anyone logged in
// would not prove a user certificate until the next network map.
func (e *Engine) watchCertificatePosture(ctx context.Context) {
	ticker := time.NewTicker(certContextPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.recollectCertificateProofsIfStale(); err != nil && !errors.Is(err, errSystemInfoTimeout) {
				log.Warnf("failed to refresh certificate posture proofs: %v", err)
			}
		}
	}
}

func (e *Engine) recollectCertificateProofsIfStale() error {
	userContext := certproof.UserContext(e.config.CertStore)
	if !e.certState.stale(userContext, time.Now()) {
		return nil
	}

	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	if e.ctx.Err() != nil || !certproof.HasChallenges(e.checks) {
		return nil
	}
	log.Debugf("certificate posture: proofs are stale, collecting again")
	return e.syncChecksMeta(e.checks)
}

// syncChecksMeta gathers the system info that checks evaluate, with its certificate
// proofs, and sends it to management. The caller holds syncMsgMux.
func (e *Engine) syncChecksMeta(checks []*mgmProto.Checks) error {
	info, ok := e.infoSource.Refresh(e.ctx, systemInfoTimeout, checks, e.overlayAddresses()...)
	if !ok {
		// Gathering timed out; skip the meta sync this cycle rather than blocking the
		// sync loop (and syncMsgMux) on a stuck system call. A later sync will retry.
		return errSystemInfoTimeout
	}
	e.applyInfoFlags(info)
	e.attachCertificateProofs(info, checks)

	if err := e.mgmClient.SyncMeta(info); err != nil {
		return fmt.Errorf("sync meta: %w", err)
	}
	return nil
}
