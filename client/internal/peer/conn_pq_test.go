package peer

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer/worker"
	signal "github.com/netbirdio/netbird/shared/signal/client"
)

// fakePQ is a minimal PQHandshaker: only PSK is exercised by presharedKey, the rest
// are no-op stubs to satisfy the interface.
type fakePQ struct {
	psk wgtypes.Key
	ok  bool
}

func (f fakePQ) OfferPayload(string) ([]byte, uint16)          { return nil, 0 }
func (f fakePQ) ShouldSendBootstrapOffer(string) bool          { return false }
func (f fakePQ) AnswerPayload(string, []byte) ([]byte, uint16) { return nil, 0 }
func (f fakePQ) OnAnswer(string, []byte)                       {}
func (f fakePQ) PSK(string) (wgtypes.Key, bool)                { return f.psk, f.ok }
func (f fakePQ) ReapplyPSK(string, *wgtypes.Key)               {}
func (f fakePQ) SetRemoteAddr(string, netip.AddrPort)          {}
func (f fakePQ) OnDataPathRekeyed(string, time.Duration)       {}
func (f fakePQ) OnDataPathDown(string)                         {}

// TestConn_presharedKey_PQ covers the post-quantum branch of presharedKey across the
// three states that matter: a derived PSK is programmed, and — before one exists —
// strict mode blocks with a sentinel while non-strict falls open to the ordinary key.
func TestConn_presharedKey_PQ(t *testing.T) {
	derivedPSK, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	nbPSK, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	newConn := func() *Conn {
		return &Conn{
			Log: log.WithField("peer", "pq-test"),
			config: ConnConfig{
				Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
				LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
				WgConfig:        WgConfig{PreSharedKey: &nbPSK},
				RosenpassConfig: RosenpassConfig{},
			},
		}
	}

	t.Run("derived PSK is programmed", func(t *testing.T) {
		for _, strict := range []bool{false, true} {
			c := newConn()
			c.config.PQ = fakePQ{psk: derivedPSK, ok: true}
			c.config.PQStrict = strict
			if strict {
				sentinel, err := wgtypes.GenerateKey()
				require.NoError(t, err)
				c.pqStrictSentinelKey = &sentinel
			}
			pqPSK, _ := c.pqPSK()
			got := c.presharedKey(nil, pqPSK)
			require.NotNil(t, got)
			require.Equal(t, derivedPSK, *got, "the derived PQ PSK must win (strict=%v)", strict)
		}
	})

	t.Run("non-strict falls open to the ordinary key before a PSK exists", func(t *testing.T) {
		c := newConn()
		c.config.PQ = fakePQ{ok: false}
		c.config.PQStrict = false
		pqPSK, _ := c.pqPSK()
		got := c.presharedKey(nil, pqPSK)
		require.NotNil(t, got, "non-strict must not block")
		require.Equal(t, nbPSK, *got, "non-strict falls through to the NetBird PSK, not a sentinel")
	})

	t.Run("strict blocks with the per-conn sentinel before a PSK exists", func(t *testing.T) {
		sentinel, err := wgtypes.GenerateKey()
		require.NoError(t, err)
		c := newConn()
		c.config.PQ = fakePQ{ok: false}
		c.config.PQStrict = true
		c.pqStrictSentinelKey = &sentinel
		pqPSK, _ := c.pqPSK()
		got := c.presharedKey(nil, pqPSK)
		require.NotNil(t, got)
		require.Equal(t, sentinel, *got, "strict must return the blocking sentinel")
		require.NotEqual(t, nbPSK, *got, "the sentinel must not be the ordinary key")
	})
}

// TestConn_IdlePresharedKey covers the key an idle (lazy) peer is installed with. Strict
// mode must never leave an idle peer without a key, since the remote can complete a
// classical handshake with it directly; everything else leaves the idle key unchanged.
func TestConn_IdlePresharedKey(t *testing.T) {
	derivedPSK, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	sentinel, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	newConn := func(pq PQHandshaker, strict bool) *Conn {
		c := &Conn{Log: log.WithField("peer", "pq-idle-test")}
		c.config.PQ = pq
		c.config.PQStrict = strict
		if strict {
			c.pqStrictSentinelKey = &sentinel
		}
		return c
	}

	got := newConn(fakePQ{ok: false}, true).IdlePresharedKey()
	require.NotNil(t, got, "strict mode must install a key on an idle peer")
	assert.Equal(t, sentinel, *got, "before a PQ PSK exists strict mode installs the sentinel")

	got = newConn(fakePQ{psk: derivedPSK, ok: true}, true).IdlePresharedKey()
	require.NotNil(t, got, "strict mode must install a key on an idle peer")
	assert.Equal(t, derivedPSK, *got, "once derived, strict mode installs the PQ PSK")

	assert.Nil(t, newConn(fakePQ{ok: false}, false).IdlePresharedKey(), "non-strict mode leaves the idle key unchanged")
	assert.Nil(t, newConn(nil, false).IdlePresharedKey(), "without ML-KEM the idle key is left unchanged")
}

// TestConn_RecoverPQKeyOverSignalOnlyWhenConnected covers the PQ recovery path. A failed KEM
// exchange makes the manager ask for a fresh signalling offer. For a peer with no
// transport (offline) that offer cannot be answered: with lazy connections off it was
// repeated at every exchange timeout, a fixed-rate stream on top of the reconnect guard's
// own backed-off offers. The recovery offer must only be sent while the peer is connected.
func TestConn_RecoverPQKeyOverSignalOnlyWhenConnected(t *testing.T) {
	newConn := func() (*Conn, *logtest.Hook) {
		logger, hook := logtest.NewNullLogger()
		logger.SetLevel(log.DebugLevel)
		entry := logger.WithField("peer", "pq-recovery-test")
		// The signal client is never ready, so an attempted offer fails fast and is logged.
		signaler := NewSignaler(&signal.MockClient{}, wgtypes.Key{})
		c := &Conn{
			Log:         entry,
			statusRelay: worker.NewAtomicStatus(),
			statusICE:   worker.NewAtomicStatus(),
		}
		c.handshaker = NewHandshaker(entry, ConnConfig{}, signaler, nil, nil, nil)
		return c, hook
	}
	offerAttempted := func(hook *logtest.Hook) bool {
		for _, e := range hook.AllEntries() {
			if strings.Contains(e.Message, "PQ key recovery over signal failed") {
				return true
			}
		}
		return false
	}

	c, hook := newConn()
	c.RecoverPQKeyOverSignal()
	assert.False(t, offerAttempted(hook), "a disconnected peer must be left to the reconnect guard")

	c, hook = newConn()
	c.statusRelay.SetConnected()
	c.RecoverPQKeyOverSignal()
	assert.True(t, offerAttempted(hook), "a connected peer must get a recovery offer")
}

// TestConn_QuantumResistant covers the status flag: Rosenpass counts only when both sides
// run it, and an established ML-KEM PSK counts on its own.
func TestConn_QuantumResistant(t *testing.T) {
	localRP := []byte("local-rosenpass-key")
	remoteRP := []byte("remote-rosenpass-key")

	cases := []struct {
		name          string
		localRP       []byte
		remoteRP      []byte
		pqEstablished bool
		want          bool
	}{
		{"nothing", nil, nil, false, false},
		{"rosenpass on both sides", localRP, remoteRP, false, true},
		{"rosenpass only locally", localRP, nil, false, false},
		{"rosenpass only remotely", nil, remoteRP, false, false},
		{"ml-kem established", nil, nil, true, true},
		{"ml-kem established, rosenpass only remotely", nil, remoteRP, true, true},
		{"ml-kem established, rosenpass on both sides", localRP, remoteRP, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := &Conn{config: ConnConfig{RosenpassConfig: RosenpassConfig{PubKey: c.localRP}}}
			assert.Equal(t, c.want, conn.quantumResistant(c.remoteRP, c.pqEstablished),
				"local rosenpass %t, remote rosenpass %t, ml-kem %t",
				c.localRP != nil, c.remoteRP != nil, c.pqEstablished)
		})
	}
}
