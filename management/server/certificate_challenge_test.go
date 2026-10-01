package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
)

// fakeClock lets a test drive the refresher's schedule without waiting for it.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// scheduleRefresher builds a refresher on a clock the test drives and never starts its
// loop, so the schedule can be checked by calling takeDue directly.
func scheduleRefresher(refresh func(accountID string) bool) (*certChallengeRefresher, *fakeClock) {
	clock := &fakeClock{at: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	r := newCertChallengeRefresher(func(_ context.Context, accountID string) bool {
		return refresh(accountID)
	})
	r.now = clock.Now
	return r, clock
}

// runningRefresher builds a refresher whose period and tick are short enough to observe
// in a test, and starts its loop.
func runningRefresher(t *testing.T, refresh func(accountID string) bool) *certChallengeRefresher {
	t.Helper()
	r := newCertChallengeRefresher(func(_ context.Context, accountID string) bool {
		return refresh(accountID)
	})
	r.period = 10 * time.Millisecond
	r.tick = time.Millisecond
	r.Start(t.Context())
	return r
}

func TestCertChallengePeriod_LeavesRoomForAMissedRun(t *testing.T) {
	// A nonce issued at the very end of a window is accepted for that window and the
	// next one only, so the shortest life a peer can be handed is one window. Renewing
	// has to stay clear of that edge even when a run is missed.
	assert.Less(t, 2*certChallengePeriod, certposture.Window,
		"a missed refresh must still leave the peer's nonce valid, with margin")
}

func TestCertChallengeRefresher_SpreadsAccountsOverThePeriod(t *testing.T) {
	// Every account on an instance shares the same global challenge window, so a
	// restart arms them all at once. The offset is what keeps them from fanning out
	// to their peers in the same moment.
	r, clock := scheduleRefresher(func(string) bool { return true })

	ids := []string{"account-a", "account-b", "account-c", "account-d", "account-e", "account-f"}
	for _, id := range ids {
		r.Track(context.Background(), id)
	}

	start := clock.Now()
	offsets := map[time.Duration]bool{}
	for _, id := range ids {
		offset := r.due[id].Sub(start)
		assert.GreaterOrEqual(t, offset, time.Duration(0), "account %s is due in the past", id)
		assert.Less(t, offset, r.period, "account %s is due beyond one period", id)
		offsets[offset] = true
	}
	assert.Greater(t, len(offsets), 1, "all accounts were given the same offset, which defeats the spreading")
}

func TestCertChallengeOffset_IsStablePerAccount(t *testing.T) {
	assert.Equal(t, offsetWithin("account-a", certChallengePeriod), offsetWithin("account-a", certChallengePeriod),
		"the same account must keep its slot across restarts")
	assert.NotEqual(t, offsetWithin("account-a", certChallengePeriod), offsetWithin("account-b", certChallengePeriod),
		"two accounts must not share a slot")
}

func TestCertChallengeRefresher_RenewsOncePerPeriod(t *testing.T) {
	r, clock := scheduleRefresher(func(string) bool { return true })
	r.Track(context.Background(), "account-a")

	assert.Empty(t, r.takeDue(), "an account just tracked is not due before its offset elapses")

	clock.Advance(r.period)
	assert.Equal(t, []string{"account-a"}, r.takeDue(), "the account is due once its offset has elapsed")

	clock.Advance(r.period / 2)
	assert.Empty(t, r.takeDue(), "the next run is booked a full period out")

	clock.Advance(r.period / 2)
	assert.Equal(t, []string{"account-a"}, r.takeDue(), "the account is due again one period later")
}

func TestCertChallengeRefresher_BooksTheNextRunBeforeRefreshing(t *testing.T) {
	// takeDue reserves the next run while it holds the lock, so a refresh that outlives
	// a tick cannot have the same account handed out twice.
	r, clock := scheduleRefresher(func(string) bool { return true })
	r.Track(context.Background(), "account-a")
	clock.Advance(r.period)

	require.Len(t, r.takeDue(), 1, "the account is due")
	assert.Empty(t, r.takeDue(), "a second pass at the same instant must not hand out the account again")
}

func TestCertChallengeRefresher_TrackIsIdempotent(t *testing.T) {
	r, clock := scheduleRefresher(func(string) bool { return true })

	r.Track(context.Background(), "account-a")
	first := r.due["account-a"]

	clock.Advance(certChallengePeriod)
	r.Track(context.Background(), "account-a")

	assert.Equal(t, first, r.due["account-a"], "re-tracking must not push the next run further out")
}

func TestCertChallengeRefresher_RefreshesATrackedAccount(t *testing.T) {
	refreshed := make(chan string, 4)
	r := runningRefresher(t, func(accountID string) bool {
		select {
		case refreshed <- accountID:
		default:
		}
		return true
	})
	r.Track(context.Background(), "account-a")

	select {
	case got := <-refreshed:
		assert.Equal(t, "account-a", got)
	case <-time.After(3 * time.Second):
		t.Fatal("a tracked account was never refreshed")
	}
	assert.True(t, r.tracked("account-a"), "an account that still wants challenges stays tracked")
}

func TestCertChallengeRefresher_DropsAnAccountThatNoLongerWantsChallenges(t *testing.T) {
	var mu sync.Mutex
	var calls int

	r := runningRefresher(t, func(string) bool {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return false
	})
	r.Track(context.Background(), "account-a")

	require.Eventually(t, func() bool { return !r.tracked("account-a") }, 3*time.Second, time.Millisecond,
		"an account whose refresh reports it no longer wants challenges must be dropped")

	time.Sleep(20 * r.tick)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, calls, "the account must not be refreshed again after being dropped")
}

func TestCertChallengeRefresher_RefreshesWithoutHoldingTheLock(t *testing.T) {
	// The refresh fans out to every peer of the account, so holding the lock across it
	// would stall every peer that connects meanwhile. Calling back into the refresher
	// from inside the refresh deadlocks if the loop still holds it.
	reentered := make(chan bool, 1)
	var once sync.Once

	r := newCertChallengeRefresher(nil)
	r.period = 10 * time.Millisecond
	r.tick = time.Millisecond
	r.refresh = func(_ context.Context, accountID string) bool {
		once.Do(func() {
			answered := make(chan bool, 1)
			go func() { answered <- r.tracked(accountID) }()
			select {
			case got := <-answered:
				reentered <- got
			case <-time.After(2 * time.Second):
				reentered <- false
			}
		})
		return true
	}
	r.Start(t.Context())
	r.Track(context.Background(), "account-a")

	select {
	case ok := <-reentered:
		assert.True(t, ok, "the refresher was not reachable while a refresh was in flight")
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh never ran")
	}
}
