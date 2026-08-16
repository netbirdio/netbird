package filedrop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	testPeer    = PeerKey("peer-pubkey")
	testProfile = profilemanager.ID("test-profile")
)

type staticResolver struct {
	key     PeerKey
	name    string
	unknown bool
}

func (r staticResolver) ResolvePeer(netip.Addr) (PeerKey, string, bool) {
	if r.unknown {
		return "", "", false
	}
	return r.key, r.name, true
}

type recordingNotifier struct {
	mu        sync.Mutex
	offers    []Offer
	completed []Offer
	failed    []Offer
	withdrawn []Offer
	progress  int
}

func (n *recordingNotifier) OnOffer(o Offer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.offers = append(n.offers, o)
}

func (n *recordingNotifier) OnProgress(Offer, int, int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.progress++
}

func (n *recordingNotifier) OnCompleted(o Offer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.completed = append(n.completed, o)
}

func (n *recordingNotifier) OnFailed(o Offer, _ error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failed = append(n.failed, o)
}

func (n *recordingNotifier) OnWithdrawn(o Offer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.withdrawn = append(n.withdrawn, o)
}

func (n *recordingNotifier) snapshot() (offers, completed, failed, withdrawn []Offer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Offer(nil), n.offers...), append([]Offer(nil), n.completed...),
		append([]Offer(nil), n.failed...), append([]Offer(nil), n.withdrawn...)
}

func startTestServer(t *testing.T, mode Mode, resolver PeerResolver) (*Server, *Client, *recordingNotifier) {
	t.Helper()

	policy := NewPolicyStore(testProfile)
	require.NoError(t, policy.Set(Policy{Mode: mode}))

	notifier := &recordingNotifier{}
	srv, err := NewServer(ServerConfig{
		SpoolDir: t.TempDir(),
		Policy:   policy,
		Resolver: resolver,
		Notifier: notifier,
		OfferTTL: 5 * time.Second,
	})
	require.NoError(t, err, "server setup must succeed")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	require.NoError(t, srv.Start(ctx, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)))
	t.Cleanup(func() {
		require.NoError(t, srv.Stop())
	})

	srv.mu.RLock()
	addr := srv.listener.Addr().String()
	srv.mu.RUnlock()

	client, err := NewClient(ClientConfig{
		SenderName:   "sender",
		PollTimeout:  2 * time.Second,
		OfferTimeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	require.NoError(t, err, "client setup must succeed")

	return srv, client, notifier
}

func filePayload(t *testing.T, name string, content []byte) Payload {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	return Payload{
		Meta: FileMeta{Name: name, Size: int64(len(content)), ContentType: "application/octet-stream"},
		Open: func(offset int64) (io.ReadCloser, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				_ = f.Close()
				return nil, err
			}
			return f, nil
		},
	}
}

var testAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, 64, 0, 1}), Port)

func TestAutoAcceptTransfersPayload(t *testing.T) {
	srv, client, notifier := startTestServer(t, ModeAutoAccept, staticResolver{key: testPeer, name: "laptop"})

	content := []byte(strings.Repeat("netbird", 1000))
	payload := filePayload(t, "report.bin", content)

	var lastSent int64
	id, err := client.Send(context.Background(), testAddr, []Payload{payload}, func(_ int, sent, _ int64) {
		lastSent = sent
	})
	require.NoError(t, err)
	require.NotEmpty(t, id, "receiver must return an offer id")

	assert.Equal(t, int64(len(content)), lastSent, "progress must reach the full payload size")

	staged, err := os.ReadFile(srv.Spool().Path(id, 0))
	require.NoError(t, err)
	assert.Equal(t, content, staged, "staged bytes should match what was sent")

	offer, ok := srv.Offers().Get(testPeer, id)
	require.True(t, ok, "offer must still be tracked")
	assert.Equal(t, StateCompleted, offer.State, "offer should be completed")
	assert.Equal(t, "laptop", offer.SenderName, "sender name should come from the resolver")

	_, completed, _, _ := notifier.snapshot()
	require.Len(t, completed, 1, "one completion event expected")
	assert.Equal(t, id, completed[0].ID)
}

func TestAskModeAcceptReleasesUpload(t *testing.T) {
	srv, client, notifier := startTestServer(t, ModeAsk, staticResolver{key: testPeer})

	content := []byte("consent required")
	payload := filePayload(t, "note.txt", content)

	go func() {
		for {
			offers, _, _, _ := notifier.snapshot()
			if len(offers) > 0 {
				srv.Offers().Decide(offers[0].ID, DecisionAccepted)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	id, err := client.Send(context.Background(), testAddr, []Payload{payload}, nil)
	require.NoError(t, err)

	staged, err := os.ReadFile(srv.Spool().Path(id, 0))
	require.NoError(t, err)
	assert.Equal(t, content, staged, "payload should arrive after acceptance")

	offers, _, _, _ := notifier.snapshot()
	require.Len(t, offers, 1, "the pending offer must be raised exactly once")
	assert.Equal(t, DecisionPending, offers[0].Decision, "the raised offer starts pending")
}

func TestAskModeDeclineKeepsPayloadOut(t *testing.T) {
	srv, client, notifier := startTestServer(t, ModeAsk, staticResolver{key: testPeer})

	go func() {
		for {
			offers, _, _, _ := notifier.snapshot()
			if len(offers) > 0 {
				srv.Offers().Decide(offers[0].ID, DecisionDeclined)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	id, err := client.Send(context.Background(), testAddr, []Payload{filePayload(t, "x.bin", []byte("data"))}, nil)
	require.ErrorIs(t, err, ErrDeclined, "sender must see the decline")

	_, statErr := os.Stat(srv.Spool().Path(id, 0))
	assert.True(t, os.IsNotExist(statErr), "declined payload must never be staged")
}

func TestOffModeRefusesOffer(t *testing.T) {
	_, client, notifier := startTestServer(t, ModeOff, staticResolver{key: testPeer})

	_, err := client.Send(context.Background(), testAddr, []Payload{filePayload(t, "x.bin", []byte("data"))}, nil)
	require.ErrorIs(t, err, ErrRefused, "an off receiver must refuse the offer")

	offers, _, _, _ := notifier.snapshot()
	assert.Empty(t, offers, "a refused offer must not reach the user")
}

func TestUnknownSenderIsRefused(t *testing.T) {
	_, client, _ := startTestServer(t, ModeAutoAccept, staticResolver{unknown: true})

	_, err := client.Send(context.Background(), testAddr, []Payload{filePayload(t, "x.bin", []byte("data"))}, nil)
	require.ErrorIs(t, err, ErrRefused, "an unresolvable source address must be refused")
}

func TestUploadResumesFromConfirmedOffset(t *testing.T) {
	srv, client, _ := startTestServer(t, ModeAutoAccept, staticResolver{key: testPeer})

	content := []byte(strings.Repeat("resume", 500))
	payload := filePayload(t, "big.bin", content)

	offer := srv.Offers().Add(testPeer, "", []FileMeta{payload.Meta}, DecisionAccepted)
	require.NoError(t, srv.Spool().Prepare(offer.ID))

	half := int64(len(content) / 2)
	_, err := srv.Spool().Write(offer.ID, 0, 0, strings.NewReader(string(content[:half])), half)
	require.NoError(t, err)

	srv.mu.RLock()
	base := "http://" + srv.listener.Addr().String()
	srv.mu.RUnlock()

	confirmed, err := client.confirmedOffset(context.Background(), base, offer.ID, 0)
	require.NoError(t, err)
	require.Equal(t, half, confirmed, "receiver must report the staged prefix")

	require.NoError(t, client.putFile(context.Background(), base, offer.ID, 0, payload, confirmed, nil))

	staged, err := os.ReadFile(srv.Spool().Path(offer.ID, 0))
	require.NoError(t, err)
	assert.Equal(t, content, staged, "resumed upload must reconstruct the full payload")
}

func TestUploadIsBoundedByAnnouncedSize(t *testing.T) {
	srv, _, _ := startTestServer(t, ModeAutoAccept, staticResolver{key: testPeer})

	// The request is issued raw: the stdlib client refuses to send a body that
	announced := int64(10)
	offer := srv.Offers().Add(testPeer, "", []FileMeta{{Name: "lie.bin", Size: announced}}, DecisionAccepted)
	require.NoError(t, srv.Spool().Prepare(offer.ID))

	srv.mu.RLock()
	addr := srv.listener.Addr().String()
	srv.mu.RUnlock()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	oversized := strings.Repeat("A", 100)
	request := "PUT /v1/offers/" + string(offer.ID) + "/files/0?offset=0 HTTP/1.1\r\n" +
		"Host: filedrop\r\nContent-Length: 100\r\nConnection: close\r\n\r\n" + oversized
	_, err = conn.Write([]byte(request))
	require.NoError(t, err)

	_, err = io.ReadAll(conn)
	require.NoError(t, err)

	staged, err := os.ReadFile(srv.Spool().Path(offer.ID, 0))
	require.NoError(t, err)
	assert.Len(t, staged, int(announced), "staged size must be capped at the announced size")
}

func TestCancelWithdrawsPendingOffer(t *testing.T) {
	srv, client, notifier := startTestServer(t, ModeAsk, staticResolver{key: testPeer})

	sendCtx, cancelSend := context.WithCancel(context.Background())
	defer cancelSend()

	go func() {
		_, _ = client.Send(sendCtx, testAddr, []Payload{filePayload(t, "x.bin", []byte("data"))}, nil)
	}()

	var id OfferID
	require.Eventually(t, func() bool {
		offers, _, _, _ := notifier.snapshot()
		if len(offers) == 0 {
			return false
		}
		id = offers[0].ID
		return true
	}, 3*time.Second, 10*time.Millisecond, "offer must reach the receiver")

	require.NoError(t, client.Cancel(context.Background(), testAddr, id))

	_, ok := srv.Offers().Get(testPeer, id)
	assert.False(t, ok, "a withdrawn offer must be dropped")

	_, _, _, withdrawn := notifier.snapshot()
	require.Len(t, withdrawn, 1, "the consent prompt must be withdrawn")
	assert.Equal(t, id, withdrawn[0].ID)
}

func TestTextPayloadStaysInline(t *testing.T) {
	srv, client, _ := startTestServer(t, ModeAutoAccept, staticResolver{key: testPeer})

	id, err := client.Send(context.Background(), testAddr, []Payload{TextPayload("snippet", "hello peer")}, nil)
	require.NoError(t, err)

	offer, ok := srv.Offers().Get(testPeer, id)
	require.True(t, ok)
	require.Len(t, offer.Files, 1)
	assert.Equal(t, "hello peer", offer.Files[0].Text, "text must arrive in the offer itself")
	assert.Equal(t, StateCompleted, offer.State, "a text-only offer completes without an upload")

	_, statErr := os.Stat(srv.Spool().Path(id, 0))
	assert.True(t, os.IsNotExist(statErr), "text payloads must not be written to the spool")
}

func TestOfferExpiresWithoutDecision(t *testing.T) {
	policy := NewPolicyStore(testProfile)
	require.NoError(t, policy.SetMode(ModeAsk))

	srv, err := NewServer(ServerConfig{
		SpoolDir: t.TempDir(),
		Policy:   policy,
		Resolver: staticResolver{key: testPeer},
		OfferTTL: 100 * time.Millisecond,
	})
	require.NoError(t, err)

	offer := srv.Offers().Add(testPeer, "", []FileMeta{{Name: "x", Size: 1}}, DecisionPending)

	awaited, err := srv.Offers().Await(context.Background(), testPeer, offer.ID)
	require.NoError(t, err)
	assert.Equal(t, DecisionExpired, awaited.Decision, "an unanswered offer must expire")
	assert.Equal(t, StateExpired, awaited.State)
}

func TestDecideIsFinal(t *testing.T) {
	store := NewOfferStore(time.Minute)
	offer := store.Add(testPeer, "", []FileMeta{{Name: "x", Size: 1}}, DecisionPending)

	_, ok := store.Decide(offer.ID, DecisionDeclined)
	require.True(t, ok, "the first decision must be recorded")

	_, ok = store.Decide(offer.ID, DecisionAccepted)
	assert.False(t, ok, "a decided offer must not be revived")

	current, ok := store.Get(testPeer, offer.ID)
	require.True(t, ok)
	assert.Equal(t, DecisionDeclined, current.Decision, "the original decision must stand")
}

func TestOfferIsScopedToItsSender(t *testing.T) {
	store := NewOfferStore(time.Minute)
	offer := store.Add(testPeer, "", []FileMeta{{Name: "x", Size: 1}}, DecisionAccepted)

	_, ok := store.Get("other-peer", offer.ID)
	assert.False(t, ok, "another peer must not see the offer")

	_, err := store.Await(context.Background(), "other-peer", offer.ID)
	assert.ErrorIs(t, err, ErrOfferNotFound, "another peer must not poll the offer")
}

func TestPolicyEvaluation(t *testing.T) {
	store := NewPolicyStore(testProfile)
	require.NoError(t, store.Set(Policy{Mode: ModeAsk}))

	assert.Equal(t, ModeAsk, store.Evaluate(testPeer), "unknown senders are asked about")

	require.NoError(t, store.SetSenderRule(testPeer, SenderRuleBlock))
	assert.Equal(t, ModeOff, store.Evaluate(testPeer), "a blocked sender is refused")

	require.NoError(t, store.SetSenderRule(testPeer, SenderRuleAlwaysAccept))
	assert.Equal(t, ModeAutoAccept, store.Evaluate(testPeer), "an always-accept sender skips the prompt")

	require.NoError(t, store.SetSenderRule(testPeer, SenderRuleDefault))
	assert.Equal(t, ModeAsk, store.Evaluate(testPeer), "clearing the rule restores the base mode")
}

func TestPolicyRejectsUnknownModeAndDeniesOnCorruptRule(t *testing.T) {
	store := NewPolicyStore(testProfile)

	require.Error(t, store.SetMode(Mode(200)), "an unknown mode must be rejected")
	assert.Equal(t, ModeAsk, store.Get().Mode, "the rejected mode must not be applied")

	require.NoError(t, store.SetSenderRule(testPeer, SenderRule(200)))
	assert.Equal(t, ModeOff, store.Evaluate(testPeer), "an unrecognized rule must deny")
}

type memStore struct {
	mu       sync.Mutex
	sections map[string][]byte
	loadErr  error
}

func newMemStore() *memStore {
	return &memStore{sections: map[string][]byte{}}
}

func (s *memStore) Get(namespace string, v any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return false, s.loadErr
	}
	raw, ok := s.sections[namespace]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, v)
}

func (s *memStore) Put(namespace string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sections[namespace] = raw
	return nil
}

func TestPolicyIsScopedPerProfile(t *testing.T) {
	work, home := profilemanager.ID("work"), profilemanager.ID("home")
	workPrefs, homePrefs := newMemStore(), newMemStore()

	workStore := LoadPolicyStore(work, workPrefs)
	require.NoError(t, workStore.SetMode(ModeOff))
	require.NoError(t, workStore.SetSenderRule(testPeer, SenderRuleBlock))

	homeStore := LoadPolicyStore(home, homePrefs)
	assert.Equal(t, ModeAsk, homeStore.Get().Mode, "another profile keeps the default mode")
	assert.Equal(t, ModeAsk, homeStore.Evaluate(testPeer), "a block in one profile must not apply to another")

	reloaded := LoadPolicyStore(work, workPrefs)
	assert.Equal(t, ModeOff, reloaded.Get().Mode, "the profile's mode must survive a reload")
	assert.Equal(t, ModeOff, reloaded.Evaluate(testPeer), "the profile's sender rule must survive a reload")
}

func TestPolicyFallsBackToDefaultsOnLoadFailure(t *testing.T) {
	prefs := newMemStore()
	prefs.loadErr = errors.New("store unavailable")

	store := LoadPolicyStore(testProfile, prefs)

	assert.Equal(t, ModeAsk, store.Get().Mode, "an unreadable policy must not open the device up")
	assert.Equal(t, ModeAsk, store.Evaluate(testPeer), "the safe default applies to unknown senders")
}

func TestPolicyRejectsStoredInvalidModeOnLoad(t *testing.T) {
	prefs := newMemStore()
	require.NoError(t, prefs.Put(namespacePolicy, Policy{Mode: Mode(200)}))

	store := LoadPolicyStore(testProfile, prefs)

	assert.Equal(t, ModeAsk, store.Get().Mode, "a corrupted stored mode must fall back to the default")
}

func TestStoreKeepsPolicyAndHistoryApart(t *testing.T) {
	prefs := newMemStore()

	mgr, err := NewManager(ManagerConfig{Profile: testProfile, DataDir: t.TempDir(), Store: prefs})
	require.NoError(t, err)
	require.NoError(t, mgr.Policy().SetMode(ModeAutoAccept))
	require.NoError(t, mgr.SetDestinationDir("/tmp/received"))
	mgr.history.Upsert(Transfer{ID: "offer-1", PeerKey: testPeer, State: StateCompleted})
	require.NoError(t, mgr.Close())

	reloaded, err := NewManager(ManagerConfig{Profile: testProfile, DataDir: t.TempDir(), Store: prefs})
	require.NoError(t, err)
	defer func() { require.NoError(t, reloaded.Close()) }()

	assert.Equal(t, ModeAutoAccept, reloaded.Policy().Get().Mode, "the policy must survive a reload")
	assert.Equal(t, "/tmp/received", reloaded.DestinationDir(), "the destination must survive a reload")
	require.Len(t, reloaded.Transfers(), 1, "the history must survive a reload")
	assert.Equal(t, OfferID("offer-1"), reloaded.Transfers()[0].ID)
}

func TestHistoryDropsOldestTerminalEntriesOverCap(t *testing.T) {
	history := LoadHistory(newMemStore())

	for i := 0; i < historyCap+10; i++ {
		history.Upsert(Transfer{ID: OfferID(fmt.Sprintf("offer-%d", i)), State: StateCompleted})
	}

	entries := history.List()
	require.Len(t, entries, historyCap, "the log must stay bounded")
	assert.Equal(t, OfferID(fmt.Sprintf("offer-%d", historyCap+9)), entries[0].ID, "the newest entry stays")
}

func TestHistoryKeepsLiveTransfersOverCap(t *testing.T) {
	history := LoadHistory(newMemStore())

	history.Upsert(Transfer{ID: "live", State: StateTransferring})
	for i := 0; i < historyCap+5; i++ {
		history.Upsert(Transfer{ID: OfferID(fmt.Sprintf("done-%d", i)), State: StateCompleted})
	}

	_, ok := history.Get("live")
	assert.True(t, ok, "a transfer still running must not be pruned")
}

func TestHistorySettlesTransfersInterruptedByRestart(t *testing.T) {
	store := newMemStore()

	history := LoadHistory(store)
	history.Upsert(Transfer{ID: "pending", State: StatePending})
	history.Upsert(Transfer{ID: "moving", State: StateTransferring})
	history.Upsert(Transfer{ID: "done", State: StateCompleted})
	history.Upsert(Transfer{ID: "refused", State: StateDeclined})

	// A fresh load stands in for the next process: nothing survives to finish
	// whatever was still moving.
	reloaded := LoadHistory(store)

	for _, tc := range []struct {
		id     OfferID
		state  State
		reason FailureReason
	}{
		{"pending", StateFailed, ReasonInterrupted},
		{"moving", StateFailed, ReasonInterrupted},
		{"done", StateCompleted, ReasonNone},
		{"refused", StateDeclined, ReasonNone},
	} {
		entry, ok := reloaded.Get(tc.id)
		require.True(t, ok, "entry %s must survive the reload", tc.id)
		assert.Equal(t, tc.state, entry.State, "state of %s", tc.id)
		assert.Equal(t, tc.reason, entry.Reason, "reason of %s", tc.id)
	}

	// The settled states are written back, so a third start sees them as final
	// rather than settling them again.
	third := LoadHistory(store)
	entry, ok := third.Get("moving")
	require.True(t, ok)
	assert.Equal(t, StateFailed, entry.State)
}

func TestSpoolWriteTruncatesStaleTail(t *testing.T) {
	spool, err := NewSpool(t.TempDir())
	require.NoError(t, err)

	id := OfferID("offer")
	require.NoError(t, spool.Prepare(id))

	_, err = spool.Write(id, 0, 0, strings.NewReader("AAAAAAAAAA"), 10)
	require.NoError(t, err)

	total, err := spool.Write(id, 0, 2, strings.NewReader("BB"), 10)
	require.NoError(t, err)
	assert.Equal(t, int64(4), total, "staged size follows the resumed write")

	staged, err := os.ReadFile(spool.Path(id, 0))
	require.NoError(t, err)
	assert.Equal(t, "AABB", string(staged), "stale bytes past the offset must be dropped")
}

func TestSpoolCleanupDropsStalePartials(t *testing.T) {
	spool, err := NewSpool(t.TempDir())
	require.NoError(t, err)

	stale, fresh := OfferID("stale"), OfferID("fresh")
	require.NoError(t, spool.Prepare(stale))
	require.NoError(t, spool.Prepare(fresh))

	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(spool.OfferDir(stale), old, old))

	spool.Cleanup(time.Hour, time.Now())

	_, err = os.Stat(spool.OfferDir(stale))
	assert.True(t, os.IsNotExist(err), "the stale offer dir must be removed")

	_, err = os.Stat(spool.OfferDir(fresh))
	assert.NoError(t, err, "a recent offer dir must survive")
}

func TestParseOfferPath(t *testing.T) {
	tests := []struct {
		path     string
		id       OfferID
		index    int
		hasIndex bool
		wantErr  bool
	}{
		{path: "/v1/offers/abc", id: "abc"},
		{path: "/v1/offers/abc/files/3", id: "abc", index: 3, hasIndex: true},
		{path: "/v1/offers/", wantErr: true},
		{path: "/v1/offers/abc/files", wantErr: true},
		{path: "/v1/offers/abc/other/1", wantErr: true},
		{path: "/v1/offers/abc/files/-1", wantErr: true},
		{path: "/v1/offers/abc/files/x", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			id, index, hasIndex, err := parseOfferPath(tc.path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.id, id)
			assert.Equal(t, tc.index, index)
			assert.Equal(t, tc.hasIndex, hasIndex)
		})
	}
}

func TestValidateOffer(t *testing.T) {
	assert.Error(t, validateOffer(nil), "an empty offer is invalid")
	assert.Error(t, validateOffer([]FileMeta{{Name: "x", Size: -1}}), "a negative size is invalid")
	assert.Error(t, validateOffer(make([]FileMeta, MaxOfferFiles+1)), "too many files is invalid")
	assert.Error(t, validateOffer([]FileMeta{{
		Name: "x", Kind: KindText, Text: strings.Repeat("a", MaxInlineTextSize+1),
	}}), "oversized inline text is invalid")

	assert.NoError(t, validateOffer([]FileMeta{{Name: "x", Size: 10}}))
}

func TestStopIsIdempotent(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		SpoolDir: t.TempDir(),
		Policy:   NewPolicyStore(testProfile),
		Resolver: staticResolver{key: testPeer},
	})
	require.NoError(t, err)

	require.NoError(t, srv.Stop(), "stopping a server that never started is a no-op")

	require.NoError(t, srv.Start(context.Background(), netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)))
	require.NoError(t, srv.Stop())
	require.NoError(t, srv.Stop(), "the second stop must also be a no-op")
}

func TestStartRejectsSecondStart(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		SpoolDir: t.TempDir(),
		Policy:   NewPolicyStore(testProfile),
		Resolver: staticResolver{key: testPeer},
	})
	require.NoError(t, err)

	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
	require.NoError(t, srv.Start(context.Background(), addr))
	t.Cleanup(func() {
		require.NoError(t, srv.Stop())
	})

	err = srv.Start(context.Background(), addr)
	require.Error(t, err, "a running server must reject a second start")

	srv.mu.RLock()
	running := srv.httpServer != nil && srv.listener != nil
	srv.mu.RUnlock()
	assert.True(t, running, "the original listener must survive the rejected start")
}

func TestNewServerRequiresResolver(t *testing.T) {
	_, err := NewServer(ServerConfig{SpoolDir: t.TempDir(), Policy: NewPolicyStore(testProfile)})
	require.Error(t, err, "a server without peer resolution must not be constructed")
}

func TestNewServerRequiresPolicy(t *testing.T) {
	_, err := NewServer(ServerConfig{SpoolDir: t.TempDir(), Resolver: staticResolver{key: testPeer}})
	require.Error(t, err, "a server without a profile policy must not be constructed")
}

func TestNewClientRequiresDialer(t *testing.T) {
	_, err := NewClient(ClientConfig{})
	require.Error(t, err, "a client without a dialer must not be constructed")
}

func TestSendRejectsEmptyPayloadSet(t *testing.T) {
	_, client, _ := startTestServer(t, ModeAutoAccept, staticResolver{key: testPeer})

	_, err := client.Send(context.Background(), testAddr, nil, nil)
	assert.True(t, errors.Is(err, ErrInvalidOffer), "sending nothing is an invalid offer")
}

func TestServerFallsBackWhenPortBusy(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "blocker listener must bind")
	defer func() {
		require.NoError(t, blocker.Close())
	}()
	busyPort := uint16(blocker.Addr().(*net.TCPAddr).Port)

	srv, err := NewServer(ServerConfig{
		SpoolDir: t.TempDir(),
		Policy:   NewPolicyStore(testProfile),
		Resolver: staticResolver{key: testPeer},
	})
	require.NoError(t, err)

	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), busyPort)
	require.NoError(t, srv.Start(context.Background(), addr), "start must fall back instead of failing")
	t.Cleanup(func() {
		require.NoError(t, srv.Stop())
	})

	bound := srv.BoundPort()
	assert.NotZero(t, bound, "fallback must report the bound port")
	assert.NotEqual(t, busyPort, bound, "fallback must pick a different port")
}

func TestPortRegistryAwait(t *testing.T) {
	reg := NewPortRegistry()

	reg.Set(testPeer, 5000)
	port, changed := reg.Await(context.Background(), testPeer, 0)
	assert.True(t, changed, "known differing port must return immediately")
	assert.Equal(t, uint16(5000), port)

	go func() {
		time.Sleep(50 * time.Millisecond)
		reg.Set(testPeer, 5000)
	}()
	_, changed = reg.Await(context.Background(), testPeer, 5000)
	assert.False(t, changed, "an advertisement equal to the used port must release the waiter as unchanged")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, changed = reg.Await(ctx, testPeer, 5000)
	assert.False(t, changed, "timeout without advertisement must report unchanged")
}

// senderManager builds a send-only manager whose dialer reaches the test server only
// on realPort; other ports behave per defaultPortBehavior ("refuse" or "hang").
func senderManager(t *testing.T, serverAddr string, realPort uint16, defaultPortBehavior string) *Manager {
	t.Helper()

	mgr, err := NewManager(ManagerConfig{Profile: testProfile, DataDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, mgr.Close())
	})

	mgr.SetTunnel(func(ctx context.Context, network, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		require.NoError(t, err, "dialer must receive a valid addr")
		if ap.Port() == realPort {
			var d net.Dialer
			return d.DialContext(ctx, network, serverAddr)
		}
		if defaultPortBehavior == "hang" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}, "sender")

	return mgr
}

func waitForState(t *testing.T, mgr *Manager, id OfferID, want State) {
	t.Helper()
	require.Eventually(t, func() bool {
		tr, ok := mgr.history.Get(id)
		return ok && tr.State == want
	}, 10*time.Second, 20*time.Millisecond, "transfer must reach state %s", want)
}

func TestSendRetriesOnAdvertisedPort(t *testing.T) {
	srv, _, _ := startTestServer(t, ModeAutoAccept, staticResolver{key: PeerKey("sender-key")})
	srv.mu.RLock()
	serverAddr := srv.listener.Addr().String()
	srv.mu.RUnlock()
	realPort := srv.BoundPort()

	mgr := senderManager(t, serverAddr, realPort, "refuse")

	id, err := mgr.Send(testPeer, "receiver", netip.AddrFrom4([4]byte{100, 64, 0, 9}), []Payload{TextPayload("t", "hello")})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	mgr.Ports().Set(testPeer, realPort)

	waitForState(t, mgr, id, StateCompleted)
}

func TestSendAbortsHangingAttemptOnAdvertisedPort(t *testing.T) {
	srv, _, _ := startTestServer(t, ModeAutoAccept, staticResolver{key: PeerKey("sender-key")})
	srv.mu.RLock()
	serverAddr := srv.listener.Addr().String()
	srv.mu.RUnlock()
	realPort := srv.BoundPort()

	mgr := senderManager(t, serverAddr, realPort, "hang")

	id, err := mgr.Send(testPeer, "receiver", netip.AddrFrom4([4]byte{100, 64, 0, 9}), []Payload{TextPayload("t", "hello")})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	mgr.Ports().Set(testPeer, realPort)

	waitForState(t, mgr, id, StateCompleted)
}

func TestSendFailsWhenSignalConfirmsUsedPort(t *testing.T) {
	mgr := senderManager(t, "127.0.0.1:1", 1, "refuse")

	id, err := mgr.Send(testPeer, "receiver", netip.AddrFrom4([4]byte{100, 64, 0, 9}), []Payload{TextPayload("t", "hello")})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	mgr.Ports().Set(testPeer, 0)

	waitForState(t, mgr, id, StateFailed)
}
