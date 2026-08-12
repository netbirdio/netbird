// Package nmaptest measures network map generation on the dedicated store
// path against committed expectations. A case stands in for the store load
// with a NetworkMapData fixture — the value NetworkMapDBStoreImpl returns for
// one account — then runs the production per-peer pipeline the controller
// uses, PeersCustomZone → GetPeerNetworkMapComponents → proto conversion, in
// both wire shapes: the legacy full map (grpc.ToSyncResponse) and the
// component envelope expanded client-side (grpc.ToComponentSyncResponse →
// networkmap.EnvelopeToNetworkMap).
//
// The expectation files are the point of the framework. They state what the
// output should be, so a failing case means the code disagrees with the
// expectation and the answer is normally to fix the code; an expectation
// changes only through a deliberate reviewed edit. Nothing in this package
// writes to testdata — there is no flag that records current behaviour into an
// expectation, because that is how a defect becomes the baseline. Cases whose
// expectation encodes correct behaviour the code does not yet deliver stay red
// on purpose.
//
// A case lives in testdata/cases/<name>/ as case.json (manifest: description,
// peers, optional accountID, dnsDomain, modes), nmdata.json (the fixture the
// mocked store returns, using Go field names; zero values may be omitted and
// applyFixtureDefaults fills the boilerplate) and golden/<peerID>.json.
//
// There is ONE expectation per peer, shared by every mode. The modes are not
// different computations: CalculateNetworkMapFromComponents is
// components.Calculate, and both sides assemble the proto with the same
// encode helpers, so the only variable is what the envelope round-trip did to
// the components in transit. Any difference between modes is therefore a
// round-trip fidelity defect, and a shared expectation is what exposes it.
// Results are canonicalized before comparison, since repeated proto fields
// come from map iteration.
package nmaptest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Mode selects the wire shape a case is verified through. Both end in a
// *proto.NetworkMap, the one comparison surface shared by every path.
type Mode string

const (
	// ModeFull is the legacy wire shape: the server runs Calculate and sends
	// the expanded map (grpc.ToSyncResponse).
	ModeFull Mode = "full"
	// ModeEnvelope is the component wire shape: the server encodes components
	// into a NetworkMapEnvelope (grpc.ToComponentSyncResponse) and the map is
	// expanded the way the client engine does (networkmap.EnvelopeToNetworkMap).
	ModeEnvelope Mode = "envelope"

	defaultAccountID = "account"
	defaultDNSDomain = "netbird.test"
)

var defaultModes = []Mode{ModeFull, ModeEnvelope}

// Case is one nmap-generation scenario: store data for a single account, the
// peers whose network maps are computed, and the directory holding one expected
// *proto.NetworkMap per peer — shared by every mode.
type Case struct {
	Name      string
	AccountID string
	DNSDomain string
	Peers     []string
	Modes     []Mode
	Data      *networkmap.NetworkMapData
	GoldenDir string
}

type manifest struct {
	Description string
	AccountID   string
	DNSDomain   string
	Peers       []string
	Modes       []Mode
}

// RunGoldenDir discovers and runs every fixture case under dir. A case is a
// directory containing case.json (manifest), nmdata.json (store fixture) and
// golden/<peerID>.json (expected proto.NetworkMap, protojson).
func RunGoldenDir(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "read cases dir")

	ran := 0
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		caseDir := filepath.Join(dir, entry.Name())
		c, err := loadCase(caseDir)
		require.NoError(t, err, "load case %s", entry.Name())
		ran++
		t.Run(entry.Name(), func(t *testing.T) {
			RunCase(t, c)
		})
	}
	require.NotZero(t, ran, "no cases found under %s", dir)
}

func loadCase(caseDir string) (Case, error) {
	raw, err := os.ReadFile(filepath.Join(caseDir, "case.json"))
	if err != nil {
		return Case{}, fmt.Errorf("read manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m manifest
	if err := dec.Decode(&m); err != nil {
		return Case{}, fmt.Errorf("decode manifest: %w", err)
	}

	data, err := LoadNetworkMapData(filepath.Join(caseDir, "nmdata.json"))
	if err != nil {
		return Case{}, err
	}

	return Case{
		Name:      filepath.Base(caseDir),
		AccountID: m.AccountID,
		DNSDomain: m.DNSDomain,
		Peers:     m.Peers,
		Modes:     m.Modes,
		Data:      data,
		GoldenDir: filepath.Join(caseDir, "golden"),
	}, nil
}

// RunCase computes each target peer's network map through every enabled mode
// and compares the canonicalized result against the peer's expectation file.
// It mirrors the controller's store path: fill fixture defaults, precompute
// posture validation once, then run the per-peer pipeline.
func RunCase(t *testing.T, c Case) {
	t.Helper()

	require.NotNil(t, c.Data, "case %s: Data is required", c.Name)
	require.NotEmpty(t, c.Peers, "case %s: Peers is required", c.Name)
	require.NotEmpty(t, c.GoldenDir, "case %s: GoldenDir is required", c.Name)
	if c.AccountID == "" {
		c.AccountID = defaultAccountID
	}
	if c.DNSDomain == "" {
		c.DNSDomain = defaultDNSDomain
	}
	if len(c.Modes) == 0 {
		c.Modes = defaultModes
	}

	ctx := context.Background()
	nmData := c.Data
	applyFixtureDefaults(nmData)
	nmData.PrecomputePostureValidation()

	dnsDomain := c.DNSDomain
	if nmData.AccountSettings.DNSDomain != "" {
		dnsDomain = nmData.AccountSettings.DNSDomain
	}

	zone := networkmap.PeersCustomZone(ctx, c.AccountID, dnsDomain, nmData.Peers, controller.IPv6AllowedPeersFromData(nmData))
	dnsFwdPort := controller.ComputeForwarderPortFromData(nmData.Peers, network_map.DnsForwarderPortMinVersion)

	for _, mode := range c.Modes {
		if mode == ModeEnvelope {
			requireEnvelopeSafeKeys(t, nmData, c.Name)
			break
		}
	}

	for _, peerID := range c.Peers {
		peer := nmData.Peers[peerID]
		require.NotNil(t, peer, "case %s: target peer %q not in fixture", c.Name, peerID)

		for _, mode := range c.Modes {
			t.Run(peerID+"/"+string(mode), func(t *testing.T) {
				got := computeMode(t, ctx, mode, nmData, peerID, zone, dnsDomain, dnsFwdPort)
				canonicalize(got)
				compareGolden(t, filepath.Join(c.GoldenDir, peerID+".json"), got, mode)
			})
		}
	}
}

// computeMode produces the peer's proto.NetworkMap the way the controller does
// for that wire shape.
func computeMode(t *testing.T, ctx context.Context, mode Mode, nmData *networkmap.NetworkMapData,
	peerID string, zone nmdata.CustomZone, dnsDomain string, dnsFwdPort int64) *proto.NetworkMap {
	t.Helper()

	peer := nmData.Peers[peerID]
	require.NotNil(t, peer, "target peer %q not in fixture", peerID)

	switch mode {
	case ModeFull:
		nmap := controller.NetworkMapFromData(ctx, nmData, peerID, zone)
		return mgmtgrpc.ToSyncResponse(ctx, nil, nil, nil, peer, nil, nil, nmap, dnsDomain, nil,
			&cache.DNSConfigCache{}, nmData.AccountSettings, nil, nil, dnsFwdPort).NetworkMap
	case ModeEnvelope:
		components := nmData.GetPeerNetworkMapComponents(peerID, zone)
		peerGroups := maps.Keys(nmData.GetPeerGroups(peerID))
		resp := mgmtgrpc.ToComponentSyncResponse(ctx, nil, nil, nil, peer, nil, nil, components, nil,
			dnsDomain, nil, nmData.AccountSettings, nil, peerGroups, dnsFwdPort)
		res, err := networkmap.EnvelopeToNetworkMap(ctx, resp.NetworkMapEnvelope, peer.Key, dnsDomain)
		require.NoError(t, err, "expand envelope")
		return res.NetworkMap
	default:
		t.Fatalf("unknown mode %q", mode)
		return nil
	}
}

// caseInputs prepares a loaded case for computation, returning the values every
// mode needs. Exposed for tests in this package that drive modes directly.
func caseInputs(t *testing.T, c Case) (*networkmap.NetworkMapData, nmdata.CustomZone, string, int64) {
	t.Helper()

	nmData := c.Data
	applyFixtureDefaults(nmData)
	nmData.PrecomputePostureValidation()

	dnsDomain := defaultDNSDomain
	if c.DNSDomain != "" {
		dnsDomain = c.DNSDomain
	}
	if nmData.AccountSettings.DNSDomain != "" {
		dnsDomain = nmData.AccountSettings.DNSDomain
	}

	accountID := c.AccountID
	if accountID == "" {
		accountID = defaultAccountID
	}

	ctx := context.Background()
	zone := networkmap.PeersCustomZone(ctx, accountID, dnsDomain, nmData.Peers, controller.IPv6AllowedPeersFromData(nmData))
	return nmData, zone, dnsDomain, controller.ComputeForwarderPortFromData(nmData.Peers, network_map.DnsForwarderPortMinVersion)
}

// requireEnvelopeSafeKeys fails fast on peer keys the envelope decoder would
// silently drop: it re-keys peers by base64 of the raw 32-byte WG public key.
func requireEnvelopeSafeKeys(t *testing.T, nmData *networkmap.NetworkMapData, caseName string) {
	t.Helper()
	for id, p := range nmData.Peers {
		if p == nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(p.Key)
		if err != nil || len(raw) != 32 {
			t.Fatalf("case %s: peer %q Key must be base64 of 32 bytes for mode %q (the envelope decoder drops it otherwise); use a real WireGuard public key or restrict the case to mode %q",
				caseName, id, ModeEnvelope, ModeFull)
		}
	}
}

// compareGolden measures got against the committed expectation file. One
// expectation serves every mode, because the modes run the same computation and
// must therefore agree. The expectation is the authority: a mismatch means the
// code does not produce what this case says it should, so it is reported as a
// failure and not quietly absorbed.
//
// The full mode is compared verbatim, identifiers included, so the expectation
// pins real ids and stays readable. Other modes have identifiers erased on both
// sides first, because the envelope currently rewrites them — a tracked defect
// that TestIDSpaceMatches asserts against on its own, so it does not have to
// drown out every other case here.
// Nothing here writes to testdata. Expectation files are authored by hand and
// only ever change through a reviewed edit, so there is no mode in which a run
// can create or replace one. When a file is missing the computed map is printed
// for the author to read and, if it is genuinely correct, save deliberately.
func compareGolden(t *testing.T, path string, got *proto.NetworkMap, mode Mode) {
	t.Helper()

	if mode != ModeFull {
		normalizeIDSpace(got)
		canonicalize(got)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		rendered, mErr := renderNetworkMap(got)
		require.NoError(t, mErr)
		t.Fatalf("no expectation file %s: %v\nThis case has nothing to measure against — write the "+
			"proto.NetworkMap this peer should receive. Mode %s currently produces:\n%s\nRead it before "+
			"saving any of it: if the code is wrong, so is this.", path, err, mode, rendered)
	}
	want := &proto.NetworkMap{}
	require.NoError(t, protojson.Unmarshal(raw, want), "parse expectation %s", path)
	canonicalize(want)
	if mode != ModeFull {
		normalizeIDSpace(want)
		canonicalize(want)
	}

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("mode %s does not produce what %s expects (-want +got):\n%s\n"+
			"Both modes run the same computation on the same components, so they must produce the same map. "+
			"The expectation file is the committed statement of correct output — fix the code, or change the "+
			"expectation deliberately if the intended behaviour really moved.", mode, path, diff)
	}
}

// renderNetworkMap renders stable protojson: protojson output whitespace is
// deliberately unstable, so it is reformatted through json.Indent.
func renderNetworkMap(nm *proto.NetworkMap) ([]byte, error) {
	raw, err := protojson.Marshal(nm)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
