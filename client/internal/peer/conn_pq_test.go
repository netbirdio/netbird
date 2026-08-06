package peer

import (
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakePQ is a minimal PQHandshaker: only PSK is exercised by presharedKey, the rest
// are no-op stubs to satisfy the interface.
type fakePQ struct {
	psk wgtypes.Key
	ok  bool
}

func (f fakePQ) OfferPayload(string) ([]byte, int)          { return nil, 0 }
func (f fakePQ) ShouldSendBootstrapOffer(string) bool       { return false }
func (f fakePQ) AnswerPayload(string, []byte) ([]byte, int) { return nil, 0 }
func (f fakePQ) OnAnswer(string, []byte)                    {}
func (f fakePQ) PSK(string) (wgtypes.Key, bool)             { return f.psk, f.ok }
func (f fakePQ) SetRemoteAddr(string, netip.AddrPort)       {}
func (f fakePQ) OnDataPathRekeyed(string, time.Duration)    {}
func (f fakePQ) OnDataPathDown(string)                      {}

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
				sentinel, _ := wgtypes.GenerateKey()
				c.pqStrictSentinelKey = &sentinel
			}
			got := c.presharedKey(nil)
			require.NotNil(t, got)
			require.Equal(t, derivedPSK, *got, "the derived PQ PSK must win (strict=%v)", strict)
		}
	})

	t.Run("non-strict falls open to the ordinary key before a PSK exists", func(t *testing.T) {
		c := newConn()
		c.config.PQ = fakePQ{ok: false}
		c.config.PQStrict = false
		got := c.presharedKey(nil)
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
		got := c.presharedKey(nil)
		require.NotNil(t, got)
		require.Equal(t, sentinel, *got, "strict must return the blocking sentinel")
		require.NotEqual(t, nbPSK, *got, "the sentinel must not be the ordinary key")
	})
}
