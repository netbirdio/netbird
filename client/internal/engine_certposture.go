package internal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/certproof"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/certposture"
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

// undeliveredContext never matches a real user context, so a collection whose meta sync
// failed is seen as stale on the next poll.
const undeliveredContext = "\x00undelivered"

// errSystemInfoTimeout reports that gathering the system info for a meta sync timed out,
// so the sync was skipped rather than holding syncMsgMux on a stuck system call.
var errSystemInfoTimeout = errors.New("system info gathering timed out")

// certPostureState remembers what the last certificate proof collection saw, so the
// engine can collect again when it went stale and tell the user when proofs go missing.
//
// Collection runs only on the posture watcher, never on the sync path, because a token,
// a TPM or a user's keychain prompt can take long; the sync path attaches the proofs the
// last collection cached. delivered identifies the chains management last received, so
// a collection that proves the same chains is not sent again: every meta sync makes
// management recompute and push network maps to the peer and its neighbours.
type certPostureState struct {
	mu          sync.Mutex
	attempted   bool
	attemptedAt time.Time
	userContext string
	proven      bool
	delivered   string
	hasDelivery bool
	cached      []certposture.Proof
	cachedFor   string
}

// record stores the outcome of a collection for the challenges identified by
// challengesKey and reports whether it changed from proven to unproven or back. The first
// collection only counts as a change when it proved nothing.
func (s *certPostureState) record(challengesKey, userContext string, proofs []certposture.Proof, now time.Time) (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	proven := len(proofs) > 0
	changed = (s.attempted && s.proven != proven) || (!s.attempted && !proven)
	s.attempted = true
	s.attemptedAt = now
	s.userContext = userContext
	s.proven = proven
	s.cached = proofs
	s.cachedFor = challengesKey
	return changed
}

// undelivered marks the last collection as not having reached management, so the next
// poll collects and sends again instead of treating it as current.
func (s *certPostureState) undelivered() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempted {
		s.userContext = undeliveredContext
	}
	s.hasDelivery = false
}

// markDelivered records the chains of proofs as the ones management holds.
func (s *certPostureState) markDelivered(proofs []certposture.Proof) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delivered = provenChainsKey(proofs)
	s.hasDelivery = true
}

// sameAsDelivered reports whether proofs prove exactly the chains management already
// holds. Nonces and signatures are left out: they differ on every signing while the
// result management stores, the verified chains, stays the same.
func (s *certPostureState) sameAsDelivered(proofs []certposture.Proof) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasDelivery && s.delivered == provenChainsKey(proofs)
}

// needsCollection reports whether the cached proofs no longer reflect what the device
// can prove for the challenges identified by challengesKey: they answer other
// challenges, the user who can answer has changed, or nothing was proven and the retry
// interval has passed.
func (s *certPostureState) needsCollection(challengesKey, userContext string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case !s.attempted || s.cachedFor != challengesKey:
		return true
	case userContext != s.userContext:
		return true
	default:
		return !s.proven && now.Sub(s.attemptedAt) >= certRetryInterval
	}
}

// cachedProofs returns the cached proofs management still accepts for the challenges in
// checks: those whose nonce is current, or from the window before, for one of them. Proofs
// signed for the previous nonce bridge the time until the watcher has signed the new one.
func (s *certPostureState) cachedProofs(checks []*mgmProto.Checks) []certposture.Proof {
	s.mu.Lock()
	defer s.mu.Unlock()

	var nonces [][]byte
	for _, check := range checks {
		if challenge := check.GetCertificateChallenge(); challenge != nil {
			nonces = append(nonces, challenge.GetNonce())
		}
	}
	var accepted []certposture.Proof
	for _, proof := range s.cached {
		if slices.ContainsFunc(nonces, func(nonce []byte) bool {
			return certposture.NonceAcceptedAlongside(proof.Nonce, nonce)
		}) {
			accepted = append(accepted, proof)
		}
	}
	return accepted
}

// provenChainsKey identifies the set of chains in proofs, independent of their order.
func provenChainsKey(proofs []certposture.Proof) string {
	keys := make([]string, 0, len(proofs))
	for _, proof := range proofs {
		h := sha256.New()
		for _, cert := range proof.Chain {
			writeLengthPrefixed(h, cert)
		}
		keys = append(keys, hex.EncodeToString(h.Sum(nil)))
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
}

// challengesKey identifies the certificate challenges in checks: their nonces and CAs.
func challengesKey(checks []*mgmProto.Checks) string {
	h := sha256.New()
	for _, check := range checks {
		challenge := check.GetCertificateChallenge()
		if challenge == nil {
			continue
		}
		writeLengthPrefixed(h, challenge.GetNonce())
		for _, ca := range challenge.GetCaCertificates() {
			writeLengthPrefixed(h, []byte(ca))
		}
		writeLengthPrefixed(h, nil)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeLengthPrefixed(h interface{ Write([]byte) (int, error) }, data []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
}

// attachCertificateProofs attaches the cached proofs management accepts for the
// challenges in checks, without collecting: the caller is on the sync path. The info is
// about to be sent on the sync stream, which resends it on every reconnect, so its proofs
// count as delivered. The watcher is woken to collect when the cache is out of date.
func (e *Engine) attachCertificateProofs(info *system.Info, checks []*mgmProto.Checks) {
	if !certproof.HasChallenges(checks) {
		info.CertificateProofs = nil
		return
	}
	info.CertificateProofs = e.certState.cachedProofs(checks)
	e.certState.markDelivered(info.CertificateProofs)
	e.wakeCertificatePosture()
}

// wakeCertificatePosture asks the posture watcher to check its proofs now rather than at
// its next tick. It never blocks.
func (e *Engine) wakeCertificatePosture() {
	if e.certWake == nil {
		return
	}
	select {
	case e.certWake <- struct{}{}:
	default:
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

// watchCertificatePosture owns certificate proof collection until ctx is done. It
// collects when woken by new checks or a sync, and on every tick when the cached proofs
// went stale, such as after a login following an autostart.
func (e *Engine) watchCertificatePosture(ctx context.Context) {
	ticker := time.NewTicker(certContextPollInterval)
	defer ticker.Stop()
	for {
		// A pending update that times out again stays pending; the applied checks'
		// proofs are still refreshed so a lost certificate is reported meanwhile.
		if err := e.retryPendingChecks(); err != nil && !errors.Is(err, errSystemInfoTimeout) {
			log.Warnf("failed to sync posture checks that timed out before: %v", err)
		}
		if err := e.refreshCertificateProofs(); err != nil && !errors.Is(err, errSystemInfoTimeout) {
			log.Warnf("failed to refresh certificate posture proofs: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-e.certWake:
		}
	}
}

// retryPendingChecks sends the meta sync for checks whose earlier sync timed out
// gathering the system info, and applies them once it succeeds. Without it they would
// wait for the next network map that changes the checks.
func (e *Engine) retryPendingChecks() error {
	if !e.hasPendingChecks.Load() {
		return nil
	}

	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	if e.ctx.Err() != nil || !e.hasPendingChecks.Load() {
		return nil
	}
	checks := e.pendingChecks
	log.Debugf("posture checks: retrying the meta sync that timed out")
	if err := e.syncChecksMeta(checks); err != nil {
		return err
	}
	e.setAppliedChecks(checks)
	e.clearPendingChecks()
	return nil
}

// refreshCertificateProofs collects the proofs for the applied checks when the cached
// ones are out of date, and sends them to management when they prove other chains than
// it holds. It holds no engine lock while collecting.
func (e *Engine) refreshCertificateProofs() error {
	checks := e.appliedChecks()
	if e.ctx.Err() != nil || !certproof.HasChallenges(checks) {
		return nil
	}
	key := challengesKey(checks)
	userContext := certproof.UserContext(e.config.CertStore)
	if !e.certState.needsCollection(key, userContext, time.Now()) {
		return nil
	}

	log.Debugf("certificate posture: collecting proofs")
	peerKey := e.config.WgPrivateKey.PublicKey()
	proofs := e.certProofs.Collect(e.ctx, checks, peerKey[:], e.config.CertStore)
	if e.certState.record(key, userContext, proofs, time.Now()) {
		e.publishCertificatePostureEvent(len(proofs) > 0)
	}

	if e.certState.sameAsDelivered(proofs) {
		log.Debugf("certificate posture: proofs unchanged since the last meta sync, not sending")
		return nil
	}
	info, ok := e.infoSource.Refresh(e.ctx, e.infoGatherTimeout(), checks, e.overlayAddresses()...)
	if !ok {
		e.certState.undelivered()
		return errSystemInfoTimeout
	}
	e.applyInfoFlags(info)
	return e.sendMetaWithProofs(info, checks)
}

// syncChecksMeta gathers the system info that checks evaluate and sends it to management
// with the cached certificate proofs. The caller holds syncMsgMux.
func (e *Engine) syncChecksMeta(checks []*mgmProto.Checks) error {
	info, ok := e.infoSource.Refresh(e.ctx, e.infoGatherTimeout(), checks, e.overlayAddresses()...)
	if !ok {
		// Gathering timed out; skip the meta sync this cycle rather than blocking the
		// sync loop (and syncMsgMux) on a stuck system call. The posture watcher retries.
		e.certState.undelivered()
		return errSystemInfoTimeout
	}
	e.applyInfoFlags(info)
	return e.sendMetaWithProofs(info, checks)
}

// sendMetaWithProofs sends info to management with the cached proofs for checks. Sends
// are serialized and read the cache under that lock, so a send from the sync path cannot
// overwrite newer proofs the watcher sent in the meantime.
func (e *Engine) sendMetaWithProofs(info *system.Info, checks []*mgmProto.Checks) error {
	e.certSendMu.Lock()
	defer e.certSendMu.Unlock()

	info.CertificateProofs = e.certState.cachedProofs(checks)
	if err := e.mgmClient.SyncMeta(info); err != nil {
		e.certState.undelivered()
		return fmt.Errorf("sync meta: %w", err)
	}
	e.certState.markDelivered(info.CertificateProofs)
	return nil
}
