//go:build !android

package iptables

import (
	"fmt"
	"maps"
	"net/netip"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbid "github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/client/internal/routemanager/ipfwdstate"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// constants needed to manage and create iptable rules
const (
	tableFilter = "filter"
	tableNat    = "nat"
	tableMangle = "mangle"

	// chainACLInput is the peer ACL chain that holds installed
	// peer-filtering rules.
	chainACLInput = "NETBIRD-ACL-INPUT"

	// mangleForwardKey is the entries map key for mangle FORWARD guard
	// rules that prevent external DNAT from bypassing ACL rules.
	mangleForwardKey chainKey = "MANGLE-FORWARD"

	chainInput       = "INPUT"
	chainPostrouting = "POSTROUTING"
	chainPrerouting  = "PREROUTING"
	chainForward     = "FORWARD"
	chainRTNAT       = "NETBIRD-RT-NAT"
	chainRTFwdIn     = "NETBIRD-RT-FWD-IN"
	chainRTFwdOut    = "NETBIRD-RT-FWD-OUT"
	chainRTPre       = "NETBIRD-RT-PRE"
	chainRTRdr       = "NETBIRD-RT-RDR"
	chainNATOutput   = "NETBIRD-NAT-OUTPUT"
	chainRTMSSClamp  = "NETBIRD-RT-MSSCLAMP"

	jumpManglePre  = "jump-mangle-pre"
	jumpNATPre     = "jump-nat-pre"
	jumpNATPost    = "jump-nat-post"
	jumpNATOutput  = "jump-nat-output"
	jumpMSSClamp   = "jump-mss-clamp"
	markManglePre  = "mark-mangle-pre"
	markManglePost = "mark-mangle-post"
	matchSet       = "--match-set"

	dnatSuffix firewall.RuleID = "_dnat"
	snatSuffix firewall.RuleID = "_snat"
	fwdSuffix  firewall.RuleID = "_fwd"

	// ipv4TCPHeaderSize is the minimum IPv4 (20) + TCP (20) header size for MSS calculation.
	ipv4TCPHeaderSize = 40
	// ipv6TCPHeaderSize is the minimum IPv6 (40) + TCP (20) header size for MSS calculation.
	ipv6TCPHeaderSize = 60
)

type ruleInfo struct {
	chain string
	table string
	rule  []string
}

type routeRules map[firewall.RuleID][]string

// ruleSpec is a single iptables rule expressed as its argument list
// (e.g. {"-i", "wg0", "-j", "DROP"}).
type ruleSpec []string

// chainKey identifies the chain a seeded entry belongs to. It holds
// built-in chain names ("INPUT", "FORWARD", "PREROUTING") plus the
// synthetic mangleForwardKey bucket for the mangle FORWARD guard rules.
type chainKey string

// aclEntries maps a chain to the rules seeded into it to jump into or
// guard the netbird ACL chains.
type aclEntries map[chainKey][]ruleSpec

type entry struct {
	spec     ruleSpec
	position int
}

// ipsetCounter is the shared hash:net refcounter used by peer and
// route ACLs alike. The ipset library does not support comments, so
// the key is just the set name (string).
type ipsetCounter = refcounter.Counter[string, []netip.Prefix, struct{}]

// family holds the per-address-family iptables state. One instance
// handles route ACLs, peer ACLs, NAT, DNAT, and MSS clamping for a
// single family; the top-level Manager owns one for v4 and another
// for v6.
type family struct {
	iptablesClient *iptables.IPTables
	wgIface        iFaceMapper
	v6             bool

	// Peer ACL chain bookkeeping.
	entries         aclEntries
	optionalEntries map[chainKey][]entry

	// filters holds peer + route filter rules keyed by content hash.
	// AddFilterRule writes here; DeleteFilterRule looks up by id.
	filters      map[nbid.RuleID]*Rule
	ipsetCounter *ipsetCounter

	// rules holds NAT, jump, and MSS-clamping rules (auxiliary
	// plumbing that isn't a filter rule).
	rules routeRules

	// Routing / NAT.
	legacyManagement bool
	mtu              uint16
	ipFwdState       *ipfwdstate.IPForwardingState

	stateManager *statemanager.Manager
}

func newFamily(iptablesClient *iptables.IPTables, wgIface iFaceMapper, mtu uint16) (*family, error) {
	r := &family{
		iptablesClient:  iptablesClient,
		wgIface:         wgIface,
		v6:              iptablesClient.Proto() == iptables.ProtocolIPv6,
		entries:         make(aclEntries),
		optionalEntries: make(map[chainKey][]entry),
		filters:         make(map[nbid.RuleID]*Rule),
		rules:           make(routeRules),
		mtu:             mtu,
		ipFwdState:      ipfwdstate.NewIPForwardingState(),
	}

	r.ipsetCounter = refcounter.New(
		func(name string, sources []netip.Prefix) (struct{}, error) {
			return struct{}{}, r.createIpSet(name, sources)
		},
		func(name string, _ struct{}) error {
			return r.deleteIpSet(name)
		},
	)

	return r, nil
}

// init wires the family to the state manager and installs both the
// route ACL containers and the peer ACL chain skeleton.
func (r *family) init(stateManager *statemanager.Manager) error {
	r.stateManager = stateManager

	if err := r.cleanUpDefaultForwardRules(); err != nil {
		log.Errorf("failed to clean up rules from FORWARD chain: %s", err)
	}

	if err := r.createContainers(); err != nil {
		return fmt.Errorf("create containers: %w", err)
	}

	if err := r.setupDataPlaneMark(); err != nil {
		log.Errorf("failed to set up data plane mark: %v", err)
	}

	r.seedInitialEntries()
	r.seedInitialOptionalEntries()

	if err := r.cleanAclChains(); err != nil {
		return fmt.Errorf("clean acl chains: %w", err)
	}
	if err := r.createDefaultChains(); err != nil {
		return fmt.Errorf("create default chains: %w", err)
	}

	r.updateState()

	return nil
}

// Reset tears down all firewall state owned by this family. ACL
// chain cleanup runs before route-chain cleanup because the route
// chains are still referenced by FORWARD jumps installed during
// seedInitialEntries; deleting them first would trip EBUSY.
func (r *family) Reset() error {
	var merr *multierror.Error

	if err := r.cleanAclChains(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.cleanUpDefaultForwardRules(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.ipsetCounter.Flush(); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.cleanupDataPlaneMark(); err != nil {
		merr = multierror.Append(merr, err)
	}

	clear(r.rules)
	clear(r.filters)
	r.updateState()

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) updateState() {
	if r.stateManager == nil {
		return
	}

	var currentState *ShutdownState
	if existing := r.stateManager.GetState(currentState); existing != nil {
		if existingState, ok := existing.(*ShutdownState); ok {
			currentState = existingState
		}
	}
	if currentState == nil {
		currentState = &ShutdownState{}
	}

	currentState.Lock()
	defer currentState.Unlock()

	// Clone the rule maps so the persisted state holds a private snapshot.
	// The live maps keep being mutated by subsequent rule operations while
	// the state manager marshals the state from its periodic-save goroutine.
	// Sharing the maps by reference races the two and aborts the process with
	// a concurrent map iteration and write. The ipset counter guards itself
	// during marshaling, so it can be shared directly.
	if r.v6 {
		currentState.RouteRules6 = maps.Clone(r.rules)
		currentState.RouteIPsetCounter6 = r.ipsetCounter
		currentState.ACLEntries6 = maps.Clone(r.entries)
	} else {
		currentState.RouteRules = maps.Clone(r.rules)
		currentState.RouteIPsetCounter = r.ipsetCounter
		currentState.ACLEntries = maps.Clone(r.entries)
	}

	if err := r.stateManager.UpdateState(currentState); err != nil {
		log.Errorf("failed to update state: %v", err)
	}
}
