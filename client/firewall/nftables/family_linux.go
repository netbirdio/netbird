//go:build !android

package nftables

import (
	"fmt"
	"net/netip"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/firewalld"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/routemanager/ipfwdstate"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

const (
	tableNat      = "nat"
	tableMangle   = "mangle"
	tableRaw      = "raw"
	tableSecurity = "security"

	chainNameNatPrerouting = "PREROUTING"
	chainNameRoutingFw     = "netbird-rt-fwd"
	chainNameRoutingNat    = "netbird-rt-postrouting"
	chainNameRoutingRdr    = "netbird-rt-redirect"
	chainNameNATOutput     = "netbird-nat-output"
	chainNameForward       = "FORWARD"
	chainNameMangleForward = "netbird-mangle-forward"

	// Peer ACL chain names.
	chainNameInputRules        = "netbird-acl-input-rules"
	chainNameInputFilter       = "netbird-acl-input-filter"
	chainNameForwardFilter     = "netbird-acl-forward-filter"
	chainNameManglePrerouting  = "netbird-mangle-prerouting"
	chainNameManglePostrouting = "netbird-mangle-postrouting"

	flushError = "flush: %w"

	firewalldTableName = "firewalld"

	userDataAcceptForwardRuleIif = "frwacceptiif"
	userDataAcceptForwardRuleOif = "frwacceptoif"
	userDataAcceptInputRule      = "inputaccept"

	dnatSuffix firewall.RuleID = "_dnat"
	snatSuffix firewall.RuleID = "_snat"

	// ipv4TCPHeaderSize is the minimum IPv4 (20) + TCP (20) header size for MSS calculation.
	ipv4TCPHeaderSize = 40
	// ipv6TCPHeaderSize is the minimum IPv6 (40) + TCP (20) header size for MSS calculation.
	ipv6TCPHeaderSize = 60

	// maxPrefixesSet 1638 prefixes start to fail, taking some margin
	maxPrefixesSet       = 1500
	refreshRulesMapError = "refresh rules map: %w"
)

var (
	errFilterTableNotFound = fmt.Errorf("'filter' table not found")
)

type setInput struct {
	set      firewall.Set
	prefixes []netip.Prefix
}

// family holds the per-address-family nftables state. One instance
// handles route ACLs, peer ACLs, NAT, DNAT, and MSS clamping for a
// single family; the top-level Manager owns one for v4 and another
// for v6. The name predates the peer-ACL absorption; it's effectively
// the per-family backend now.
type family struct {
	conn        *nftables.Conn
	workTable   *nftables.Table
	filterTable *nftables.Table
	chains      map[string]*nftables.Chain

	// filters holds peer + route filter rules keyed by content hash.
	// AddFilterRule writes here; DeleteFilterRule looks up by id.
	filters map[firewall.RuleID]*Rule

	// rules holds NAT, DNAT, and external accept rules (auxiliary
	// plumbing that isn't a filter rule).
	rules map[firewall.RuleID]*nftables.Rule

	// Peer ACL chain handles.
	chainInputRules    *nftables.Chain
	chainPrerouting    *nftables.Chain
	routingFwChainName string

	ipsetCounter *refcounter.Counter[string, setInput, *nftables.Set]

	af               addrFamily
	wgIface          iFaceMapper
	ipFwdState       *ipfwdstate.IPForwardingState
	legacyManagement bool
	mtu              uint16
}

func newFamily(workTable *nftables.Table, wgIface iFaceMapper, mtu uint16) *family {
	r := &family{
		conn:               &nftables.Conn{},
		workTable:          workTable,
		chains:             make(map[string]*nftables.Chain),
		filters:            make(map[firewall.RuleID]*Rule),
		rules:              make(map[firewall.RuleID]*nftables.Rule),
		routingFwChainName: chainNameRoutingFw,
		af:                 familyForAddr(workTable.Family == nftables.TableFamilyIPv4),
		wgIface:            wgIface,
		ipFwdState:         ipfwdstate.NewIPForwardingState(),
		mtu:                mtu,
	}

	r.ipsetCounter = refcounter.New(
		r.createIpSet,
		r.deleteIpSet,
	)

	var err error
	r.filterTable, err = r.loadFilterTable()
	if err != nil {
		log.Debugf("ip filter table not found: %v", err)
	}

	return r
}

func (r *family) init(workTable *nftables.Table) error {
	r.workTable = workTable

	if err := r.removeAcceptFilterRules(); err != nil {
		log.Errorf("failed to clean up rules from filter table: %s", err)
	}

	if err := r.createContainers(); err != nil {
		return fmt.Errorf("create containers: %w", err)
	}

	if err := r.setupDataPlaneMark(); err != nil {
		log.Errorf("failed to set up data plane mark: %v", err)
	}

	if err := r.createDefaultChains(); err != nil {
		return fmt.Errorf("create default acl chains: %w", err)
	}

	return nil
}

// Reset cleans existing nftables filter table rules from the system
func (r *family) Reset() error {
	// clear without deleting the ipsets, the nf table will be deleted by the caller
	r.ipsetCounter.Clear()

	var merr *multierror.Error

	if err := r.removeAcceptFilterRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove accept filter rules: %w", err))
	}

	if err := firewalld.UntrustInterface(r.wgIface.Name()); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.removeNatPreroutingRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove filter prerouting rules: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) loadFilterTable() (*nftables.Table, error) {
	tables, err := r.conn.ListTablesOfFamily(r.af.tableFamily)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	for _, table := range tables {
		if table.Name == "filter" {
			return table, nil
		}
	}

	return nil, errFilterTableNotFound
}

func hookName(hook *nftables.ChainHook) string {
	if hook == nil {
		return "unknown"
	}
	switch *hook {
	case *nftables.ChainHookForward:
		return chainNameForward
	case *nftables.ChainHookInput:
		return chainNameInput
	default:
		return fmt.Sprintf("hook(%d)", *hook)
	}
}

func familyName(family nftables.TableFamily) string {
	switch family {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	default:
		return fmt.Sprintf("family(%d)", family)
	}
}

func (r *family) iptablesProto() iptables.Protocol {
	if r.af.tableFamily == nftables.TableFamilyIPv6 {
		return iptables.ProtocolIPv6
	}
	return iptables.ProtocolIPv4
}

func (r *family) refreshRulesMap() error {
	var merr *multierror.Error
	newRules := make(map[firewall.RuleID]*nftables.Rule)
	for _, chain := range r.chains {
		rules, err := r.conn.GetRules(chain.Table, chain)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("list rules for chain %s: %w", chain.Name, err))
			// preserve existing entries for this chain since we can't verify their state
			for k, v := range r.rules {
				if v.Chain != nil && v.Chain.Name == chain.Name {
					newRules[k] = v
				}
			}
			continue
		}
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				newRules[firewall.RuleID(rule.UserData)] = rule
			}
		}
	}
	r.rules = newRules
	return nberrors.FormatErrorOrNil(merr)
}
