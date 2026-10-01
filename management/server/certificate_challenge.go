package server

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/certposture"
)

const (
	minCertChallengeTick = time.Second
	maxCertChallengeTick = 15 * time.Minute
)

// certChallengePeriod is how often an account whose policies carry a certificate
// posture check is pushed a fresh challenge. A nonce is accepted for its own window and
// the one before it, so one issued at the very end of a window lives only one window. A
// third of that leaves a missed run well clear of the edge, where a half would put it
// exactly on it.
func certChallengePeriod() time.Duration {
	return certposture.EffectiveWindow() / 3
}

// certChallengeTick is how often the refresher looks for accounts that are due. It is
// derived from the period rather than fixed, so shortening the challenge window for a
// test shortens this with it; the bounds keep a tiny window from spinning and a normal
// one from checking less often than is useful.
func certChallengeTick(period time.Duration) time.Duration {
	return min(max(period/10, minCertChallengeTick), maxCertChallengeTick)
}

// certChallengeRefresher pushes a fresh certificate challenge to the peers of every
// account that needs one, from a single goroutine.
//
// A nonce only reaches a peer attached to a network map, and a quiet account sends no
// map. Without this the peer re-sends an expired nonce on its next sync, management
// rejects its whole proof set and drops its certificates, and it loses every policy
// gated on the check until something else changes.
//
// Accounts are held in a map rather than a queue ordered by due time: one pass over
// them every certChallengeTick costs nothing next to a period measured in hours, and it
// avoids having to re-arm a timer whenever an account that falls due sooner is added.
type certChallengeRefresher struct {
	mu  sync.Mutex
	due map[string]time.Time

	period time.Duration
	tick   time.Duration
	now    func() time.Time
	// refresh pushes the account's peers an update, and reports whether the account
	// still wants challenges at all.
	refresh func(ctx context.Context, accountID string) bool
}

func newCertChallengeRefresher(refresh func(ctx context.Context, accountID string) bool) *certChallengeRefresher {
	period := certChallengePeriod()
	return &certChallengeRefresher{
		due:     map[string]time.Time{},
		period:  period,
		tick:    certChallengeTick(period),
		now:     time.Now,
		refresh: refresh,
	}
}

// Start runs the refresh loop until ctx is done.
func (r *certChallengeRefresher) Start(ctx context.Context) {
	go r.run(ctx)
}

// Track starts refreshing accountID, spreading its first run over one period so that a
// global window rollover does not fan out to every account in the same moment. An
// account already tracked keeps the schedule it has.
func (r *certChallengeRefresher) Track(ctx context.Context, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.due[accountID]; ok {
		return
	}
	r.due[accountID] = r.now().Add(offsetWithin(accountID, r.period))
	log.WithContext(ctx).Debugf("tracking certificate challenge refresh for account %s", accountID)
}

// Forget stops refreshing accountID.
func (r *certChallengeRefresher) Forget(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.due, accountID)
}

func (r *certChallengeRefresher) tracked(accountID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.due[accountID]
	return ok
}

func (r *certChallengeRefresher) run(ctx context.Context) {
	ticker := time.NewTicker(r.tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, accountID := range r.takeDue() {
				if !r.refresh(ctx, accountID) {
					r.Forget(accountID)
				}
			}
		}
	}
}

// takeDue returns the accounts due now and books their next run straight away, so a
// slow refresh cannot make an account fall due twice, and so the refresh itself runs
// without the lock.
func (r *certChallengeRefresher) takeDue() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	var due []string
	for accountID, at := range r.due {
		if at.After(now) {
			continue
		}
		due = append(due, accountID)
		r.due[accountID] = now.Add(r.period)
	}
	return due
}

// offsetWithin maps a key to a stable duration in [0, period).
func offsetWithin(key string, period time.Duration) time.Duration {
	h := fnv.New64a()
	//nolint:errcheck // hash.Write never returns an error
	h.Write([]byte(key))
	return time.Duration(binary.BigEndian.Uint64(h.Sum(nil)) % uint64(period))
}

// refreshCertificateChallenges pushes the account's peers an update so each one is
// stamped with a nonce for the current window, and reports whether the account still
// has a certificate posture check to refresh for.
func (am *DefaultAccountManager) refreshCertificateChallenges(ctx context.Context, accountID string) bool {
	wanted, err := am.accountNeedsCertificateChallenges(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("cannot tell whether account %s still needs certificate challenges: %v", accountID, err)
		// Keep the account tracked: a store error now says nothing about its checks.
		return true
	}
	if !wanted {
		log.WithContext(ctx).Debugf("account %s has no certificate posture check left, stopping challenge refresh", accountID)
		return false
	}

	log.WithContext(ctx).Debugf("refreshing certificate challenges for account %s", accountID)
	am.UpdateAccountPeers(ctx, accountID, types.UpdateReason{
		Resource:  types.UpdateResourcePostureCheck,
		Operation: types.UpdateOperationRefresh,
	})
	return true
}

// trackCertificateChallenges starts refreshing the account's certificate challenges if
// it has a posture check that asks for one.
func (am *DefaultAccountManager) trackCertificateChallenges(ctx context.Context, accountID string) {
	if am.certChallenges.tracked(accountID) {
		return
	}

	wanted, err := am.accountNeedsCertificateChallenges(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("cannot tell whether account %s needs certificate challenges: %v", accountID, err)
		return
	}
	if !wanted {
		return
	}
	am.certChallenges.Track(ctx, accountID)
}

// accountNeedsCertificateChallenges reports whether any of the account's posture checks
// asks its peers to prove a certificate.
func (am *DefaultAccountManager) accountNeedsCertificateChallenges(ctx context.Context, accountID string) (bool, error) {
	checks, err := am.Store.GetAccountPostureChecks(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}
	for _, check := range checks {
		if check.Checks.CertificateCheck != nil {
			return true, nil
		}
	}
	return false, nil
}
