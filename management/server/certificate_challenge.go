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

// certChallengeRefresher pushes a fresh certificate challenge to the peers connected to
// this instance that answer one, from a single goroutine.
//
// A nonce only reaches a peer attached to a network map, and a quiet account sends no
// map, so without this the peer eventually re-sends an expired nonce, has its whole
// proof set rejected, and silently leaves the policies the check gates.
//
// Each instance renews only the peers whose sync stream it holds, so a peer is renewed
// once however many instances run, and an account is dropped as soon as none of its
// peers here answers a challenge.
type certChallengeRefresher struct {
	mu       sync.Mutex
	accounts map[string]*certChallengeAccount
	// refreshing holds the accounts whose refresh is running, and whether Track was
	// called for one meanwhile, which makes its refresh's verdict stale.
	refreshing map[string]bool

	period  time.Duration
	tick    time.Duration
	timeout time.Duration
	now     func() time.Time
	// refresh pushes an update to those of peerIDs that answer a certificate challenge,
	// and reports whether any of them does.
	refresh func(ctx context.Context, accountID string, peerIDs []string) bool
}

// certChallengeAccount is one account's renewal schedule and the peers it covers, each
// with the start of the sync stream it was stamped on.
type certChallengeAccount struct {
	due   time.Time
	peers map[string]time.Time
}

// certChallengeDue is an account handed out for refresh, with its peers at that moment.
type certChallengeDue struct {
	accountID string
	peerIDs   []string
}

func newCertChallengeRefresher(refresh func(ctx context.Context, accountID string, peerIDs []string) bool) *certChallengeRefresher {
	period := certChallengePeriod()
	tick := certChallengeTick(period)
	return &certChallengeRefresher{
		accounts:   map[string]*certChallengeAccount{},
		refreshing: map[string]bool{},
		period:     period,
		tick:       tick,
		timeout:    certChallengeRefresh(tick),
		now:        time.Now,
		refresh:    refresh,
	}
}

// Start runs the refresh loop until ctx is done.
func (r *certChallengeRefresher) Start(ctx context.Context) {
	go r.run(ctx)
}

// Track renews the challenge of peerID, which was stamped one on the sync stream that
// started at streamStart. An account seen for the first time has its first run spread
// over one period, so that a global window rollover does not fan out to every account in
// the same moment; an account already tracked keeps its schedule.
func (r *certChallengeRefresher) Track(ctx context.Context, accountID, peerID string, streamStart time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.refreshing[accountID]; ok {
		r.refreshing[accountID] = true
	}
	account, ok := r.accounts[accountID]
	if !ok {
		account = &certChallengeAccount{
			due:   r.now().Add(offsetWithin(accountID, r.period)),
			peers: map[string]time.Time{},
		}
		r.accounts[accountID] = account
		log.WithContext(ctx).Debugf("tracking certificate challenge refresh for account %s", accountID)
	}
	account.peers[peerID] = streamStart
}

// Untrack stops renewing peerID once the sync stream that started at streamStart ends.
// A newer stream of the same peer keeps it tracked. The account is dropped with its
// last peer.
func (r *certChallengeRefresher) Untrack(accountID, peerID string, streamStart time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account, ok := r.accounts[accountID]
	if !ok {
		return
	}
	if started, ok := account.peers[peerID]; !ok || !started.Equal(streamStart) {
		return
	}
	delete(account.peers, peerID)
	if len(account.peers) == 0 {
		delete(r.accounts, accountID)
	}
}

// Forget stops refreshing accountID.
func (r *certChallengeRefresher) Forget(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.accounts, accountID)
}

func (r *certChallengeRefresher) tracked(accountID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.accounts[accountID]
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
			for _, due := range r.takeDue() {
				r.finish(due.accountID, r.refreshOne(ctx, due))
			}
		}
	}
}

// refreshOne refreshes a single account under the refresh deadline. A refresh that runs
// out of time reports the account as still wanting challenges, since a deadline says
// nothing about the account's posture checks; the next sweep tries again.
func (r *certChallengeRefresher) refreshOne(ctx context.Context, due certChallengeDue) bool {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.refresh(ctx, due.accountID, due.peerIDs)
}

// finish records the outcome of an account's refresh. An account none of whose peers
// answers a challenge any more is dropped, unless one was tracked again while the
// refresh ran: the refresh may have read the store before a certificate check was added.
// A dropped peer is tracked again the next time it is stamped a challenge.
func (r *certChallengeRefresher) finish(accountID string, wanted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	retracked := r.refreshing[accountID]
	delete(r.refreshing, accountID)
	if !wanted && !retracked {
		delete(r.accounts, accountID)
	}
}

// takeDue returns the accounts due now and books their next run straight away, so a
// slow refresh cannot make an account fall due twice, and so the refresh itself runs
// without the lock.
func (r *certChallengeRefresher) takeDue() []certChallengeDue {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	var due []certChallengeDue
	for accountID, account := range r.accounts {
		if account.due.After(now) {
			continue
		}
		due = append(due, certChallengeDue{accountID: accountID, peerIDs: slices.Collect(maps.Keys(account.peers))})
		account.due = now.Add(r.period)
		r.refreshing[accountID] = false
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

// refreshCertificateChallenges pushes an update to those of peerIDs that answer a
// certificate challenge, so each is stamped with a nonce for the current window. It
// reports whether any of them answers one.
func (am *DefaultAccountManager) refreshCertificateChallenges(ctx context.Context, accountID string, peerIDs []string) bool {
	targets, err := am.certificateChallengeTargets(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("cannot resolve the certificate challenge targets of account %s: %v", accountID, err)
		// Keep the account tracked: a store error now says nothing about its checks.
		return true
	}
	peerIDs = slices.DeleteFunc(peerIDs, func(id string) bool { return !slices.Contains(targets, id) })
	if len(peerIDs) == 0 {
		log.WithContext(ctx).Debugf("no peer of account %s on this instance answers a certificate challenge, stopping challenge refresh", accountID)
		return false
	}

	log.WithContext(ctx).Debugf("refreshing certificate challenges for %d peers of account %s", len(peerIDs), accountID)
	reason := types.UpdateReason{Resource: types.UpdateResourcePostureCheck, Operation: types.UpdateOperationRefresh}
	if err := am.networkMapController.BufferUpdateAffectedPeers(ctx, accountID, peerIDs, reason); err != nil {
		log.WithContext(ctx).Warnf("failed refreshing certificate challenges for account %s: %v", accountID, err)
	}
	return true
}

// certificateChallengeTargets returns the peers that are sent a certificate challenge.
// Only those peers hold a nonce, so pushing to the whole account would wake every peer
// that never uses the feature.
//
// It is the inverse of processPeerPostureChecks, which decides the same thing one peer
// at a time; TestCertificateChallengeTargets_MatchesThePerPeerRule holds them together.
func (am *DefaultAccountManager) certificateChallengeTargets(ctx context.Context, accountID string) ([]string, error) {
	certCheckIDs, err := am.certificatePostureCheckIDs(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if len(certCheckIDs) == 0 {
		return nil, nil
	}

	policies, err := am.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	groups, err := am.Store.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	groupPeers := make(map[string][]string, len(groups))
	for _, g := range groups {
		groupPeers[g.ID] = g.Peers
	}

	return certificateChallengeTargets(policies, groupPeers, certCheckIDs), nil
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

// TrackCertificateChallenges starts renewing the certificate challenge of a peer that was
// stamped one on the sync stream started at streamStart. It is called on every stamped
// update, so it has to stay cheap: no store access, just a map the refresher sweeps.
func (am *DefaultAccountManager) TrackCertificateChallenges(ctx context.Context, accountID, peerID string, streamStart time.Time) {
	am.certChallenges.Track(ctx, accountID, peerID, streamStart)
}

// UntrackCertificateChallenges stops renewing the certificate challenge of a peer whose
// sync stream started at streamStart has ended.
func (am *DefaultAccountManager) UntrackCertificateChallenges(accountID, peerID string, streamStart time.Time) {
	am.certChallenges.Untrack(accountID, peerID, streamStart)
}
