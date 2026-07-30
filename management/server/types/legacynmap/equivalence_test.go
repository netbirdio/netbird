//go:build nmapequiv

// Main-vs-branch equivalence check. For every peer of every account in a real
// Postgres copy it computes the client-facing proto.NetworkMap twice:
//
//   - legacy path: main's Account → NetworkMapComponents → Calculate → proto
//     (the frozen copy in this package)
//   - new path:    this branch's Account → NetworkMapData → components →
//     Calculate → ToSyncResponse → proto
//
// proto.NetworkMap is generated code identical in both trees, which is what
// makes it the one usable comparison surface — the intermediate Go types differ
// by design. proto.Equal would trip over repeated-field ordering, so both sides
// are canonicalized first.
//
//	NETBIRD_STORE_ENGINE_POSTGRES_DSN='...' go test -tags nmapequiv \
//	  -run TestNetworkMapProtoEquivalence -count=1 -timeout 60m \
//	  ./management/server/types/legacynmap/
//
// Accounts are loaded one at a time and released between iterations, so peak
// memory tracks the largest single account rather than the whole database.
//
// Env knobs: NETMAP_ACCOUNTS (comma-separated ids, skips discovery),
// NETMAP_MAX_ACCOUNTS (0 = all), NETMAP_MAX_PEERS (0 = all). Fails at the
// first divergence.
package legacynmap_test

import (
	"bytes"
	"cmp"
	"context"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	goproto "google.golang.org/protobuf/proto"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/types/legacynmap"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	equivDNSName  = "netbird.cloud"
	progressEvery = 5000
)

type equivStats struct {
	accounts     int
	peersChecked int
	skippedNilNM int
}

func TestNetworkMapProtoEquivalence(t *testing.T) {
	if testing.Short() {
		t.Skip("prod-db equivalence test, skipped in short mode")
	}
	dsn := equivDSN()
	if dsn == "" {
		t.Skip("NETBIRD_STORE_ENGINE_POSTGRES_DSN not set")
	}

	ctx := context.Background()
	// skipMigration=true: this reads a restored production copy and must not
	// alter its schema. Flip to false only if reads fail on an older dump.
	testStore, err := store.NewPostgresqlStore(ctx, dsn, nil, true)
	require.NoError(t, err, "connect to postgres")
	t.Cleanup(func() { testStore.Close(ctx) })

	accountIDs := equivAccountIDs(t, dsn)
	require.NotEmpty(t, accountIDs, "no accounts selected")

	stats := &equivStats{accounts: len(accountIDs)}
	maxPeers := envInt("NETMAP_MAX_PEERS", 0)

	for i, accountID := range accountIDs {
		account, err := testStore.GetAccount(ctx, accountID)
		if err != nil {
			t.Logf("account %s: load failed, skipping: %v", accountID, err)
			continue
		}

		checkAccount(ctx, t, account, maxPeers, stats)

		account = nil
		debug.FreeOSMemory()

		if i%progressEvery == 0 {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			t.Logf("progress: accounts=%d/%d peers_checked=%d heap=%dMiB", i, len(accountIDs), stats.peersChecked, ms.HeapAlloc>>20)
		}
	}

	t.Logf("equivalence: accounts=%d peers_checked=%d skipped_nil_nm=%d — no divergence",
		stats.accounts, stats.peersChecked, stats.skippedNilNM)
}

// checkAccount compares both paths for every peer of one account. Nothing is
// retained across peers, so memory stays flat within an account.
func checkAccount(ctx context.Context, t *testing.T, account *types.Account, maxPeers int, stats *equivStats) {
	t.Helper()

	if len(account.Peers) == 0 {
		return
	}

	validated := make(map[string]struct{}, len(account.Peers))
	peerIDs := make([]string, 0, len(account.Peers))
	for peerID := range account.Peers {
		validated[peerID] = struct{}{}
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	if maxPeers > 0 && len(peerIDs) > maxPeers {
		peerIDs = peerIDs[:maxPeers]
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupUsers := account.GetActiveGroupUsers()

	settings := account.Settings
	if settings == nil {
		settings = &types.Settings{}
	}

	for _, peerID := range peerIDs {
		peer := account.Peers[peerID]
		if peer == nil {
			continue
		}

		// NEW PATH — this branch, through the production conversion.
		newNM := account.GetPeerNetworkMapFromComponents(
			ctx, peerID, nbdns.CustomZone{}, nil, validated, resourcePolicies, routers, nil, groupUsers,
		)
		if newNM == nil {
			stats.skippedNilNM++
			continue
		}
		newProto := mgmtgrpc.ToSyncResponse(
			ctx, nil, nil, nil, peer, nil, nil, newNM, equivDNSName, nil,
			&cache.DNSConfigCache{}, settings, settings.Extra, nil, 0,
		).NetworkMap

		// LEGACY PATH — main's frozen copy.
		legacyNM := legacynmap.GetPeerNetworkMapFromComponents(
			account, ctx, peerID, nbdns.CustomZone{}, nil, validated, resourcePolicies, routers, nil, groupUsers,
		)
		if legacyNM == nil {
			t.Fatalf("after %d peers: account=%s peer=%s legacy NetworkMap nil, new non-nil", stats.peersChecked, account.Id, peerID)
		}
		// A separate cache per side: sharing one would let the first path
		// populate entries the second then reuses, which can mask a real diff.
		legacyProto := legacynmap.ToProtoNetworkMap(
			ctx, peer, legacyNM, equivDNSName, settings, nil, &cache.DNSConfigCache{}, 0,
		)

		canonicalize(legacyProto)
		canonicalize(newProto)
		stats.peersChecked++

		if !goproto.Equal(legacyProto, newProto) {
			t.Fatalf("after %d peers: %s", stats.peersChecked, describeDivergence(legacyProto, newProto, account.Id, peerID))
		}
	}
}

func equivDSN() string {
	if dsn := os.Getenv("NETBIRD_STORE_ENGINE_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return os.Getenv("NB_STORE_ENGINE_POSTGRES_DSN")
}

// equivAccountIDs lists account ids with an id-only query. store.GetAllAccounts
// would hydrate every account in the database before the first comparison runs.
// Sorting happens in Go so the order does not depend on database collation.
func equivAccountIDs(t *testing.T, dsn string) []string {
	t.Helper()

	if ids := strings.TrimSpace(os.Getenv("NETMAP_ACCOUNTS")); ids != "" {
		var out []string
		for _, id := range strings.Split(ids, ",") {
			if id = strings.TrimSpace(id); id != "" {
				out = append(out, id)
			}
		}
		sort.Strings(out)
		return out
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err, "open id-listing connection")
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	}()

	var ids []string
	require.NoError(t, db.Model(&types.Account{}).Pluck("id", &ids).Error)
	sort.Strings(ids)

	if max := envInt("NETMAP_MAX_ACCOUNTS", 0); max > 0 && len(ids) > max {
		ids = ids[:max]
	}
	return ids
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// canonicalize sorts every repeated field by a stable key. Both paths iterate Go
// maps while building these slices, so order can differ even when the content is
// identical; without this proto.Equal reports noise.
func canonicalize(nm *proto.NetworkMap) {
	if nm == nil {
		return
	}
	slices.SortFunc(nm.RemotePeers, cmpRemotePeer)
	slices.SortFunc(nm.OfflinePeers, cmpRemotePeer)
	slices.SortFunc(nm.Routes, cmpRoute)
	slices.SortFunc(nm.FirewallRules, cmpFirewallRule)
	slices.SortFunc(nm.RoutesFirewallRules, cmpRouteFirewallRule)
	slices.SortFunc(nm.ForwardingRules, cmpForwardingRule)

	for _, r := range nm.FirewallRules {
		slices.SortFunc(r.SourcePrefixes, bytes.Compare)
	}
	for _, r := range nm.RoutesFirewallRules {
		slices.Sort(r.SourceRanges)
	}
	canonicalizeDNSConfig(nm.DNSConfig)
	canonicalizeSSHAuth(nm.SshAuth)
}

func canonicalizeDNSConfig(d *proto.DNSConfig) {
	if d == nil {
		return
	}
	for _, g := range d.NameServerGroups {
		if g == nil {
			continue
		}
		slices.Sort(g.Domains)
		slices.SortFunc(g.NameServers, func(a, b *proto.NameServer) int {
			if a == nil || b == nil {
				return boolCmp(a == nil, b == nil)
			}
			if c := cmp.Compare(a.IP, b.IP); c != 0 {
				return c
			}
			if c := cmp.Compare(a.Port, b.Port); c != 0 {
				return c
			}
			return cmp.Compare(a.NSType, b.NSType)
		})
	}
	slices.SortFunc(d.NameServerGroups, func(a, b *proto.NameServerGroup) int {
		return cmp.Compare(nsgKey(a), nsgKey(b))
	})
	for _, z := range d.CustomZones {
		if z == nil {
			continue
		}
		slices.SortFunc(z.Records, cmpSimpleRecord)
	}
	slices.SortFunc(d.CustomZones, func(a, b *proto.CustomZone) int {
		if a == nil || b == nil {
			return boolCmp(a == nil, b == nil)
		}
		return cmp.Compare(a.Domain, b.Domain)
	})
}

// canonicalizeSSHAuth sorts AuthorizedUsers and re-keys MachineUsers.Indexes
// against the new ordering, preserving which machine user maps to which hashes.
func canonicalizeSSHAuth(s *proto.SSHAuth) {
	if s == nil || len(s.AuthorizedUsers) == 0 {
		return
	}
	type hashed struct {
		bytes []byte
		old   uint32
	}
	entries := make([]hashed, len(s.AuthorizedUsers))
	for i, b := range s.AuthorizedUsers {
		entries[i] = hashed{bytes: b, old: uint32(i)}
	}
	slices.SortFunc(entries, func(a, b hashed) int { return bytes.Compare(a.bytes, b.bytes) })

	remap := make(map[uint32]uint32, len(entries))
	sorted := make([][]byte, len(entries))
	for newIdx, e := range entries {
		remap[e.old] = uint32(newIdx)
		sorted[newIdx] = e.bytes
	}
	s.AuthorizedUsers = sorted

	for _, mu := range s.MachineUsers {
		if mu == nil {
			continue
		}
		for i, oldIdx := range mu.Indexes {
			if newIdx, ok := remap[oldIdx]; ok {
				mu.Indexes[i] = newIdx
			}
		}
		slices.Sort(mu.Indexes)
	}
}

func boolCmp(a, b bool) int {
	if a == b {
		return 0
	}
	if a {
		return 1
	}
	return -1
}

func nsgKey(g *proto.NameServerGroup) string {
	if g == nil {
		return ""
	}
	var parts []string
	for _, ns := range g.NameServers {
		if ns == nil {
			continue
		}
		parts = append(parts, ns.IP+":"+strconv.FormatInt(ns.Port, 10)+":"+strconv.FormatInt(ns.NSType, 10))
	}
	slices.Sort(parts)
	key := strings.Join(parts, ",")
	domains := append([]string(nil), g.Domains...)
	slices.Sort(domains)
	key += "|" + strings.Join(domains, "|")
	if g.Primary {
		key += "|P"
	}
	if g.SearchDomainsEnabled {
		key += "|S"
	}
	return key
}

func cmpSimpleRecord(a, b *proto.SimpleRecord) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Type, b.Type); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Class, b.Class); c != 0 {
		return c
	}
	if c := cmp.Compare(a.RData, b.RData); c != 0 {
		return c
	}
	return cmp.Compare(a.TTL, b.TTL)
}

func cmpRemotePeer(a, b *proto.RemotePeerConfig) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	return cmp.Compare(a.WgPubKey, b.WgPubKey)
}

func cmpRoute(a, b *proto.Route) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := cmp.Compare(a.ID, b.ID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.NetID, b.NetID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Network, b.Network); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Peer, b.Peer); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Metric, b.Metric); c != 0 {
		return c
	}
	return slices.Compare(a.Domains, b.Domains)
}

func cmpFirewallRule(a, b *proto.FirewallRule) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := bytes.Compare(a.PolicyID, b.PolicyID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.PeerIP, b.PeerIP); c != 0 { //nolint:staticcheck
		return c
	}
	if c := cmp.Compare(int32(a.Direction), int32(b.Direction)); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Action), int32(b.Action)); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Port, b.Port); c != 0 {
		return c
	}
	return cmp.Compare(portInfoKey(a.PortInfo), portInfoKey(b.PortInfo))
}

func cmpRouteFirewallRule(a, b *proto.RouteFirewallRule) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := bytes.Compare(a.PolicyID, b.PolicyID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.RouteID, b.RouteID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Destination, b.Destination); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); c != 0 {
		return c
	}
	if c := cmp.Compare(portInfoKey(a.PortInfo), portInfoKey(b.PortInfo)); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Action), int32(b.Action)); c != 0 {
		return c
	}
	if c := slices.Compare(a.Domains, b.Domains); c != 0 {
		return c
	}
	if c := slices.Compare(a.SourceRanges, b.SourceRanges); c != 0 {
		return c
	}
	if c := cmp.Compare(a.CustomProtocol, b.CustomProtocol); c != 0 {
		return c
	}
	return boolCmp(a.IsDynamic, b.IsDynamic)
}

func cmpForwardingRule(a, b *proto.ForwardingRule) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); c != 0 {
		return c
	}
	return bytes.Compare(a.TranslatedAddress, b.TranslatedAddress)
}

func portInfoKey(pi *proto.PortInfo) string {
	if pi == nil {
		return ""
	}
	switch sel := pi.PortSelection.(type) {
	case *proto.PortInfo_Port:
		return "P" + strconv.FormatUint(uint64(sel.Port), 10)
	case *proto.PortInfo_Range_:
		if sel.Range == nil {
			return "R"
		}
		return "R" + strconv.FormatUint(uint64(sel.Range.Start), 10) + "-" + strconv.FormatUint(uint64(sel.Range.End), 10)
	}
	return ""
}

// describeDivergence names the first differing field so a failure is actionable
// without re-running against the database.
func describeDivergence(legacy, updated *proto.NetworkMap, accountID, peerID string) string {
	prefix := "account=" + accountID + " peer=" + peerID

	lens := []struct {
		field string
		a, b  int
	}{
		{"RemotePeers", len(legacy.RemotePeers), len(updated.RemotePeers)},
		{"OfflinePeers", len(legacy.OfflinePeers), len(updated.OfflinePeers)},
		{"Routes", len(legacy.Routes), len(updated.Routes)},
		{"FirewallRules", len(legacy.FirewallRules), len(updated.FirewallRules)},
		{"RoutesFirewallRules", len(legacy.RoutesFirewallRules), len(updated.RoutesFirewallRules)},
		{"ForwardingRules", len(legacy.ForwardingRules), len(updated.ForwardingRules)},
	}
	for _, l := range lens {
		if l.a != l.b {
			return prefix + " field=" + l.field + " legacy_len=" + strconv.Itoa(l.a) + " new_len=" + strconv.Itoa(l.b)
		}
	}

	for i := range legacy.RemotePeers {
		if !goproto.Equal(legacy.RemotePeers[i], updated.RemotePeers[i]) {
			return prefix + " field=RemotePeers[" + strconv.Itoa(i) + "] legacy=" + protoStr(legacy.RemotePeers[i]) + " new=" + protoStr(updated.RemotePeers[i])
		}
	}
	for i := range legacy.Routes {
		if !goproto.Equal(legacy.Routes[i], updated.Routes[i]) {
			return prefix + " field=Routes[" + strconv.Itoa(i) + "] legacy=" + protoStr(legacy.Routes[i]) + " new=" + protoStr(updated.Routes[i])
		}
	}
	for i := range legacy.FirewallRules {
		if !goproto.Equal(legacy.FirewallRules[i], updated.FirewallRules[i]) {
			return prefix + " field=FirewallRules[" + strconv.Itoa(i) + "] legacy=" + protoStr(legacy.FirewallRules[i]) + " new=" + protoStr(updated.FirewallRules[i])
		}
	}
	for i := range legacy.RoutesFirewallRules {
		if !goproto.Equal(legacy.RoutesFirewallRules[i], updated.RoutesFirewallRules[i]) {
			return prefix + " field=RoutesFirewallRules[" + strconv.Itoa(i) + "] legacy=" + protoStr(legacy.RoutesFirewallRules[i]) + " new=" + protoStr(updated.RoutesFirewallRules[i])
		}
	}
	if !goproto.Equal(legacy.PeerConfig, updated.PeerConfig) {
		return prefix + " field=PeerConfig legacy=" + protoStr(legacy.PeerConfig) + " new=" + protoStr(updated.PeerConfig)
	}
	if !goproto.Equal(legacy.DNSConfig, updated.DNSConfig) {
		return prefix + " field=DNSConfig legacy=" + protoStr(legacy.DNSConfig) + " new=" + protoStr(updated.DNSConfig)
	}
	if !goproto.Equal(legacy.SshAuth, updated.SshAuth) {
		return prefix + " field=SshAuth legacy=" + protoStr(legacy.SshAuth) + " new=" + protoStr(updated.SshAuth)
	}
	if legacy.Serial != updated.Serial {
		return prefix + " field=Serial legacy=" + strconv.FormatUint(legacy.Serial, 10) + " new=" + strconv.FormatUint(updated.Serial, 10)
	}
	return prefix + " (repeated fields equal element-wise — scalar/oneof mismatch)"
}

func protoStr(m goproto.Message) string {
	if m == nil {
		return "<nil>"
	}
	s := prototext.Format(m)
	const maxLen = 800
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}
