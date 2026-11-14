package alignedhb

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

var (
	// lastSigned holds the last phase Management signed for this client. The
	// Management, Signal and relay clients are separate objects, and the Signal
	// and relay streams can reopen while Management is gone, so the phase
	// outlives the Management stream. Only mobile clients store a phase, and
	// they run one client per process, so the store has one slot per process.
	lastSigned atomic.Pointer[storedPhase]

	// storeMu serializes stores, so seq grows with each new phase and every
	// store closes the channel its waiters hold.
	storeMu   sync.Mutex
	storeSeq  uint64
	changedCh = make(chan struct{})
)

// answerCh is closed and replaced on every aligned Management answer.
// Guarded by storeMu.
var answerCh = make(chan struct{})

// storedPhase is a signed phase with the peer and period it was signed for.
type storedPhase struct {
	peer   messages.PeerID
	period time.Duration
	signed SignedPhase
	seq    uint64
}

// StoredPhase is the last phase Management signed, with the period it was
// signed for. Seq grows with every new phase, so a stream that sent Seq knows
// whether a newer one came since.
type StoredPhase struct {
	Period time.Duration
	Signed SignedPhase
	Seq    uint64
}

// StoreSignedPhase records the phase Management signed for peer and period.
// Signal and relay clients send it when their streams open, and to their open
// streams when it changes. Storing the phase that is already stored changes
// nothing.
func StoreSignedPhase(peer messages.PeerID, period time.Duration, sp SignedPhase) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if lastSigned.Load().same(peer, period, sp) {
		return
	}
	sp.Signature = bytes.Clone(sp.Signature)
	storeSeq++
	lastSigned.Store(&storedPhase{peer: peer, period: period, signed: sp, seq: storeSeq})
	close(changedCh)
	changedCh = make(chan struct{})
}

// SignedPhaseChanged returns a channel that is closed when the next new phase
// is stored. Load the phase after taking the channel, so no store is missed.
func SignedPhaseChanged() <-chan struct{} {
	storeMu.Lock()
	defer storeMu.Unlock()
	return changedCh
}

// ClearSignedPhase drops the stored phase of peer, for example when Management
// turns the aligned heartbeat off. A phase stored for another peer stays.
func ClearSignedPhase(peer messages.PeerID) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if cur := lastSigned.Load(); cur != nil && cur.peer == peer {
		lastSigned.Store(nil)
	}
}

// LoadSignedPhase returns the last phase Management signed for peer and the
// period it was signed for. ok is false when there is none, or when the stored
// phase belongs to another peer, as after an account switch.
func LoadSignedPhase(peer messages.PeerID) (period time.Duration, sp SignedPhase, ok bool) {
	stored, ok := LoadStoredPhase(peer)
	return stored.Period, stored.Signed, ok
}

// LoadStoredPhase is LoadSignedPhase with the sequence number of the phase.
func LoadStoredPhase(peer messages.PeerID) (StoredPhase, bool) {
	cur := lastSigned.Load()
	if cur == nil || cur.peer != peer {
		return StoredPhase{}, false
	}
	sp := cur.signed
	sp.Signature = bytes.Clone(sp.Signature)
	return StoredPhase{Period: cur.period, Signed: sp, Seq: cur.seq}, true
}

// AnnounceSignedAnswer tells the Signal client that Management answered the
// aligned heartbeat with a signed phase, also when that phase is the stored
// one. A stock stream behind a proxy can outlive the stock server it opened on,
// and an unchanged phase wakes no SignedPhaseChanged waiter.
func AnnounceSignedAnswer() {
	storeMu.Lock()
	defer storeMu.Unlock()
	close(answerCh)
	answerCh = make(chan struct{})
}

// SignedAnswerAnnounced returns a channel that is closed on the next
// AnnounceSignedAnswer.
func SignedAnswerAnnounced() <-chan struct{} {
	storeMu.Lock()
	defer storeMu.Unlock()
	return answerCh
}

func (s *storedPhase) same(peer messages.PeerID, period time.Duration, sp SignedPhase) bool {
	return s != nil && s.peer == peer && s.period == period && s.signed.Phase == sp.Phase &&
		s.signed.Day == sp.Day && bytes.Equal(s.signed.Signature, sp.Signature)
}
