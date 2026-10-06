package server

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"maps"
	"slices"
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

	maxCertChallengeRefresh = 30 * time.Second
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

// certChallengeRefresh is how long one account's refresh is given before it is
// abandoned. Resolving the target peers reads the store and accounts are swept one
// after another, so an unbounded refresh lets one wedged read starve all the others.
func certChallengeRefresh(tick time.Duration) time.Duration {
	return min(tick, maxCertChallengeRefresh)
}

// certChallengeRefresher pushes a fresh certificate challenge to the peers of every
// account that needs one, from a single goroutine.
//
// A nonce only reaches a peer attached to a network map, and a quiet account sends no
// map, so without this the peer eventually re-sends an expired nonce, has its whole
// proof set rejected, and silently leaves the policies the check gates.
//
// Accounts live in a map rather than a queue ordered by due time: one pass per tick
// costs nothing next to a period measured in hours, and nothing has to be re-armed.
type certChallengeRefresher struct {
	mu  sync.Mutex
	due map[string]time.Time

	period  time.Duration
	tick    time.Duration
	timeout time.Duration
	now     func() time.Time
	// refresh pushes the account's peers an update, and reports whether the account
	// still wants challenges at all.
	refresh func(ctx context.Context, accountID string) bool
}

func newCertChallengeRefresher(refresh func(ctx context.Context, accountID string) bool) *certChallengeRefresher {
	period := certChallengePeriod()
	tick := certChallengeTick(period)
	return &certChallengeRefresher{
		due:     map[string]time.Time{},
		period:  period,
		tick:    tick,
		timeout: certChallengeRefresh(tick),
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
				if !r.refreshOne(ctx, accountID) {
					r.Forget(accountID)
				}
			}
		}
	}
}

// refreshOne refreshes a single account under the refresh deadline. A refresh that runs
// out of time reports the account as still wanting challenges, since a deadline says
// nothing about the account's posture checks; the next sweep tries again.
func (r *certChallengeRefresher) refreshOne(ctx context.Context, accountID string) bool {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.refresh(ctx, accountID)
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

// refreshCertificateChallenges pushes an update to the peers that answer a certificate
// challenge, so each is stamped with a nonce for the current window. It reports whether
// the account still has a certificate posture check to refresh for.
func (am *DefaultAccountManager) refreshCertificateChallenges(ctx context.Context, accountID string) bool {
	peerIDs, wanted, err := am.certificateChallengeTargets(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("cannot resolve the certificate challenge targets of account %s: %v", accountID, err)
		// Keep the account tracked: a store error now says nothing about its checks.
		return true
	}
	if !wanted {
		log.WithContext(ctx).Debugf("account %s has no certificate posture check left, stopping challenge refresh", accountID)
		return false
	}
	if len(peerIDs) == 0 {
		log.WithContext(ctx).Tracef("account %s has a certificate posture check but no peer answers it yet", accountID)
		return true
	}

	log.WithContext(ctx).Debugf("refreshing certificate challenges for %d peers of account %s", len(peerIDs), accountID)
	reason := types.UpdateReason{Resource: types.UpdateResourcePostureCheck, Operation: types.UpdateOperationRefresh}
	if err := am.networkMapController.BufferUpdateAffectedPeers(ctx, accountID, peerIDs, reason); err != nil {
		log.WithContext(ctx).Warnf("failed refreshing certificate challenges for account %s: %v", accountID, err)
	}
	return true
}

// certificateChallengeTargets returns the peers that are sent a certificate challenge,
// and whether the account asks for one at all. Only those peers hold a nonce, so
// pushing to the whole account would wake every peer that never uses the feature.
//
// It is the inverse of processPeerPostureChecks, which decides the same thing one peer
// at a time; TestCertificateChallengeTargets_MatchesThePerPeerRule holds them together.
func (am *DefaultAccountManager) certificateChallengeTargets(ctx context.Context, accountID string) ([]string, bool, error) {
	certCheckIDs, err := am.certificatePostureCheckIDs(ctx, accountID)
	if err != nil {
		return nil, false, err
	}
	if len(certCheckIDs) == 0 {
		return nil, false, nil
	}

	policies, err := am.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, true, err
	}
	groups, err := am.Store.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, true, err
	}
	groupPeers := make(map[string][]string, len(groups))
	for _, g := range groups {
		groupPeers[g.ID] = g.Peers
	}

	return certificateChallengeTargets(policies, groupPeers, certCheckIDs), true, nil
}

// certificateChallengeTargets collects the source peers of every enabled policy whose
// posture checks include a certificate check.
func certificateChallengeTargets(policies []*types.Policy, groupPeers map[string][]string, certCheckIDs map[string]struct{}) []string {
	targets := map[string]struct{}{}
	for _, policy := range policies {
		if !policy.Enabled || !slices.ContainsFunc(policy.SourcePostureChecks, func(id string) bool {
			_, ok := certCheckIDs[id]
			return ok
		}) {
			continue
		}
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}
			if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
				targets[rule.SourceResource.ID] = struct{}{}
			}
			for _, groupID := range rule.Sources {
				for _, peerID := range groupPeers[groupID] {
					targets[peerID] = struct{}{}
				}
			}
		}
	}
	return slices.Collect(maps.Keys(targets))
}

// certificatePostureCheckIDs returns the IDs of the account's posture checks that ask a
// peer to prove a certificate.
func (am *DefaultAccountManager) certificatePostureCheckIDs(ctx context.Context, accountID string) (map[string]struct{}, error) {
	checks, err := am.Store.GetAccountPostureChecks(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	ids := map[string]struct{}{}
	for _, check := range checks {
		if check.Checks.CertificateCheck != nil {
			ids[check.ID] = struct{}{}
		}
	}
	return ids, nil
}

// TrackCertificateChallenges starts renewing an account's certificate challenges. It is
// called wherever a nonce is issued, so it has to stay cheap: no store access, just a
// map the refresher sweeps.
func (am *DefaultAccountManager) TrackCertificateChallenges(ctx context.Context, accountID string) {
	am.certChallenges.Track(ctx, accountID)
}
