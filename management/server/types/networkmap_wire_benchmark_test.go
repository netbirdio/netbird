package types_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	goproto "google.golang.org/protobuf/proto"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/types"
)

// wireBenchScales — trimmed scale set for wire-size measurements. Encoding
// and marshalling are linear, so the largest extremes don't add signal.
var wireBenchScales = []benchmarkScale{
	{"100peers_5groups", 100, 5},
	{"500peers_20groups", 500, 20},
	{"1000peers_50groups", 1000, 50},
	{"5000peers_100groups", 5000, 100},
}

// populateAccountSeqIDs assigns deterministic AccountSeqIDs to every group and
// policy in the account so that the component encoder can reference them. The
// scalableTestAccount fixture builds entities by struct literal and skips this
// step, but production paths populate the IDs via the store layer.
func populateAccountSeqIDs(account *types.Account) {
	var nextGroupSeq uint32 = 1
	for _, g := range account.Groups {
		g.AccountSeqID = nextGroupSeq
		nextGroupSeq++
	}
	var nextPolicySeq uint32 = 1
	for _, p := range account.Policies {
		p.AccountSeqID = nextPolicySeq
		nextPolicySeq++
	}
}

// assignValidWgKeys overwrites every peer's Key with a valid base64-encoded
// 32-byte string. The default scalableTestAccount uses unparsable strings
// like "key-peer-0", which makes the components encoder emit a nil WgPubKey
// and the legacy encoder ship 10-char placeholders — both shrink the wire
// size in unrealistic ways. Production peers always have valid 44-char base64
// keys, so any benchmark/breakdown that wants honest numbers must call this.
func assignValidWgKeys(account *types.Account) {
	for _, p := range account.Peers {
		var raw [32]byte
		_, _ = rand.Read(raw[:])
		p.Key = base64.StdEncoding.EncodeToString(raw[:])
	}
}

// BenchmarkNetworkMapWireEncode reports per-call ns and the marshaled wire
// size for both encoding paths. Run with:
//
//	go test -run=^$ -bench=BenchmarkNetworkMapWireEncode -benchmem ./management/server/types/
func BenchmarkNetworkMapWireEncode(b *testing.B) {
	skipCIBenchmark(b)

	for _, scale := range wireBenchScales {
		account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
		populateAccountSeqIDs(account)
		assignValidWgKeys(account)

		ctx := context.Background()
		resourcePolicies := account.GetResourcePoliciesMap()
		routers := account.GetResourceRoutersMap()
		groupIDToUserIDs := account.GetActiveGroupUsers()

		peerID := "peer-0"
		peer := account.Peers[peerID]

		networkMap := account.GetPeerNetworkMapFromComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
		components := account.GetPeerNetworkMapComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, groupIDToUserIDs)

		dnsCache := &cache.DNSConfigCache{}
		settings := &types.Settings{}

		// Pre-encode once so the size metric is identical for every run inside
		// the same scale; the b.Loop call only re-runs encode + Marshal.
		legacyResp := mgmtgrpc.ToSyncResponse(ctx, nil, nil, nil, peer, nil, nil, networkMap, "netbird.cloud", nil, dnsCache, settings, nil, nil, 0)
		legacyBytes, err := goproto.Marshal(legacyResp.NetworkMap)
		if err != nil {
			b.Fatalf("marshal legacy networkmap: %v", err)
		}

		envelopeInput := mgmtgrpc.ComponentsEnvelopeInput{
			Components: components,
			PeerConfig: legacyResp.NetworkMap.PeerConfig,
			DNSDomain:  "netbird.cloud",
		}
		envelope := mgmtgrpc.EncodeNetworkMapEnvelope(envelopeInput)
		envelopeBytes, err := goproto.Marshal(envelope)
		if err != nil {
			b.Fatalf("marshal envelope: %v", err)
		}

		b.Run(fmt.Sprintf("legacy/%s", scale.name), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(len(legacyBytes)), "bytes/msg")
			b.ResetTimer()
			for range b.N {
				resp := mgmtgrpc.ToSyncResponse(ctx, nil, nil, nil, peer, nil, nil, networkMap, "netbird.cloud", nil, dnsCache, settings, nil, nil, 0)
				if _, err := goproto.Marshal(resp.NetworkMap); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("components/%s", scale.name), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(len(envelopeBytes)), "bytes/msg")
			b.ResetTimer()
			for range b.N {
				env := mgmtgrpc.EncodeNetworkMapEnvelope(envelopeInput)
				if _, err := goproto.Marshal(env); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNetworkMapWireSize is a fast snapshot of the wire size by scale
// without a tight encode loop. Run with -bench to see one ns/op + bytes per
// scale (treat the timing as informational; the sample is one Marshal per
// scale, not the full b.N loop).
func BenchmarkNetworkMapWireSize(b *testing.B) {
	skipCIBenchmark(b)

	for _, scale := range wireBenchScales {
		account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
		populateAccountSeqIDs(account)
		assignValidWgKeys(account)

		ctx := context.Background()
		resourcePolicies := account.GetResourcePoliciesMap()
		routers := account.GetResourceRoutersMap()
		groupIDToUserIDs := account.GetActiveGroupUsers()

		peerID := "peer-0"
		peer := account.Peers[peerID]

		networkMap := account.GetPeerNetworkMapFromComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
		components := account.GetPeerNetworkMapComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, groupIDToUserIDs)

		dnsCache := &cache.DNSConfigCache{}
		settings := &types.Settings{}

		legacyResp := mgmtgrpc.ToSyncResponse(ctx, nil, nil, nil, peer, nil, nil, networkMap, "netbird.cloud", nil, dnsCache, settings, nil, nil, 0)
		legacyBytes, err := goproto.Marshal(legacyResp.NetworkMap)
		if err != nil {
			b.Fatalf("marshal legacy networkmap: %v", err)
		}

		env := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
			Components: components,
			PeerConfig: legacyResp.NetworkMap.PeerConfig,
			DNSDomain:  "netbird.cloud",
		})
		envBytes, err := goproto.Marshal(env)
		if err != nil {
			b.Fatalf("marshal envelope: %v", err)
		}

		b.Run(fmt.Sprintf("size/%s", scale.name), func(b *testing.B) {
			b.ReportMetric(float64(len(legacyBytes)), "legacy_bytes")
			b.ReportMetric(float64(len(envBytes)), "components_bytes")
			ratio := float64(len(envBytes)) / float64(len(legacyBytes))
			b.ReportMetric(ratio, "components/legacy")
			for range b.N {
			}
		})
	}
}
