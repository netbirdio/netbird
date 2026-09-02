package networkmapdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/miekg/dns"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

var ErrDnsUnsupportedRecordType = errors.New("unsupported record type")

type NetworkMapDBStore interface { //nolint:revive // established name across the codebase
	BeginTx(ctx context.Context) (NetworkMapDBStoreConn, error)
	Exec(ctx context.Context, query string, args ...any) error
}

type NetworkMapDBStoreConn interface { //nolint:revive // established name across the codebase
	GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, map[string]map[string]any, error)
	GetDomains(ctx context.Context, accountId string) ([]Domain, error)
	GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error)
	GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error)
	GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error)
	GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error)
	GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error)
	GetNetworkRouters(ctx context.Context, accountId string) (map[string]map[string]*nmdata.NetworkRouter, error)
	GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error)
	GetAppliedZoneCandidates(ctx context.Context, accountId string) ([]networkmap.AppliedZoneCandidate, error)
	GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error)
	GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, map[string]string, error)
	GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error)
	GetDnsSettings(ctx context.Context, accountId string) (nmdata.DNSSettings, error)
	GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error)
	GetPrivateServices(ctx context.Context, accountId string) ([]Service, error)
	GetProxyTargetedDomainResourceIDs(ctx context.Context, accountId string) (map[string]struct{}, error)

	CommitTx(ctx context.Context) error
	RollbackTx(ctx context.Context) error
}

type NetworkMapDBStoreImpl struct { //nolint:revive // established name across the codebase
	Store                   NetworkMapDBStore
	IntegratedPeerValidator integrated_validator.IntegratedValidator
	ExtraSettingsManager    settings.Manager
}

// The order of fields in these structs is important.
// Mapping of results of sqlite queries relies on the order
// of the fields in these structs, when a query or a struct changes,
// corresponding changes must be made to its counterpart.

type Account struct {
	PeerLoginExpirationEnabled      sql.NullBool
	PeerLoginExpiration             sql.NullInt64
	PeerInactivityExpirationEnabled sql.NullBool
	PeerInactivityExpiration        sql.NullInt64
	DNSDomain                       sql.NullString
	IPv6EnabledGroups               []byte `nmap:"json"`
	RoutingPeerDNSResolutionEnabled sql.NullBool
	LazyConnectionEnabled           sql.NullBool
	AutoUpdateVersion               sql.NullString
	AutoUpdateAlways                sql.NullBool
	MetricsPushEnabled              sql.NullBool
}

type Domain struct {
	Domain        sql.NullString
	TargetCluster sql.NullString
}

type Service struct {
	Enabled      sql.NullBool
	Private      sql.NullBool
	AccessGroups []string
	ProxyCluster sql.NullString
	Domain       sql.NullString
}

type Zone struct {
	Id                   string `nmap:"skip"`
	Domain               sql.NullString
	SearchDomainDisabled sql.NullBool
	DistributionGroups   []byte         `nmap:"skip,json"`
	RecordName           sql.NullString `nmap:"skip"`
	RecordType           sql.NullString `nmap:"skip"`
	RecordClass          sql.NullString `nmap:"skip"`
	RecordTTL            sql.NullInt64  `nmap:"skip"`
	RecordRData          sql.NullString `nmap:"skip"`
}

type NameserverGroup struct {
	ID                   string
	PublicID             sql.NullString
	Name                 sql.NullString
	Description          sql.NullString
	NameServers          []byte `nmap:"json"`
	Groups               []byte `nmap:"json"`
	Primary              sql.NullBool
	Domains              []byte `nmap:"json"`
	Enabled              sql.NullBool
	SearchDomainsEnabled sql.NullBool
}

type Networkresource struct {
	ID          string
	NetworkID   sql.NullString
	AccountID   sql.NullString
	PublicID    sql.NullString
	Name        sql.NullString
	Description sql.NullString
	Type        sql.NullString
	Domain      sql.NullString
	Prefix      []byte `nmap:"json"`
	Enabled     sql.NullBool
}

type AccountNetwork struct {
	Identifier sql.NullString
	Net        []byte `nmap:"json"`
	NetV6      []byte `nmap:"json"`
	Dns        sql.NullString
	Serial     sql.NullInt64
}

type Network struct {
	ID       string
	PublicID sql.NullString
}

type Policy struct {
	ID                  string
	PublicID            sql.NullString
	Enabled             sql.NullBool
	SourcePostureChecks []byte         `nmap:"json"`
	RuleEnabled         sql.NullBool   `nmap:"skip"`
	Action              sql.NullString `nmap:"skip"`
	Protocol            sql.NullString `nmap:"skip"`
	Bidirectional       sql.NullBool   `nmap:"skip"`
	Sources             []byte         `nmap:"skip,json"`
	Destinations        []byte         `nmap:"skip,json"`
	SourceResource      []byte         `nmap:"skip,json"`
	DestinationResource []byte         `nmap:"skip,json"`
	Ports               []byte         `nmap:"skip,json"`
	PortRanges          []byte         `nmap:"skip,json"`
	AuthorizedGroups    []byte         `nmap:"skip,json"`
	AuthorizedUser      sql.NullString `nmap:"skip"`
	SessionPubKey       sql.NullString `nmap:"skip"`
	SessionDisplayName  sql.NullString `nmap:"skip"`
}

// Depending on db interface LastLogin contains time in different formats:
// for sqlite/sql.NullTime the time in UTC
// for pgx the time is in the local timezone
// TODO add support for creating struct fields from denormalized fields
type Peer struct {
	ID                         string
	Key                        sql.NullString
	SSHKey                     sql.NullString
	DNSLabel                   sql.NullString
	ExtraDNSLabels             []byte `nmap:"json"`
	UserID                     sql.NullString
	SSHEnabled                 sql.NullBool
	LoginExpirationEnabled     sql.NullBool
	LastLogin                  sql.NullTime
	IP                         []byte         `nmap:"json"`
	IPv6                       []byte         `nmap:"json"`
	PeerStatusRequiresApproval sql.NullBool   `nmap:"map_to:RequiresApproval"`
	PeerStatusConnected        sql.NullBool   `nmap:"skip"`
	ProxyMetaEmbedded          sql.NullBool   `nmap:"skip"`
	ProxyMetaCluster           sql.NullString `nmap:"skip"`
	MetaWtVersion              sql.NullString `nmap:"skip"`
	MetaGoOS                   sql.NullString `nmap:"skip"`
	MetaOSVersion              sql.NullString `nmap:"skip"`
	MetaKernelVersion          sql.NullString `nmap:"skip"`
	MetaNetworkAddresses       []byte         `nmap:"skip,json"`
	MetaFiles                  []byte         `nmap:"skip,json"`
	MetaCapabilities           []byte         `nmap:"skip,json"`
	MetaFlags                  []byte         `nmap:"skip,json"`
	MetaSyncMessageVersion     sql.NullInt64  `nmap:"skip"`
	LocationCountryCode        sql.NullString `nmap:"skip"`
	LocationCityName           sql.NullString `nmap:"skip"`
	LocationConnectionIp       []byte         `nmap:"skip,json"`
}

type PostureChecks struct {
	ID       string
	PublicID sql.NullString `nmap:"skip"`
	Checks   []byte         `nmap:"json"`
}

type Route struct {
	ID                  string
	AccountID           sql.NullString
	PublicID            sql.NullString
	Network             []byte `nmap:"json"`
	Domains             []byte `nmap:"json"`
	KeepRoute           sql.NullBool
	NetID               sql.NullString
	Description         sql.NullString
	Peer                sql.NullString
	PeerID              sql.NullString
	PeerGroups          []byte `nmap:"json"`
	NetworkType         sql.NullInt64
	Masquerade          sql.NullBool
	Metric              sql.NullInt64
	Enabled             sql.NullBool
	Groups              []byte `nmap:"json"`
	AccessControlGroups []byte `nmap:"json"`
	SkipAutoApply       sql.NullBool
}

func RecordTypeAndRdata(t, rdata string) (int, string, error) {
	switch t {
	case "A":
		return int(dns.TypeA), rdata, nil
	case "AAAA":
		return int(dns.TypeAAAA), rdata, nil
	case "CNAME":
		return int(dns.TypeCNAME), dns.Fqdn(rdata), nil
	default:
		return 0, "", fmt.Errorf("record type: %s %w", t, ErrDnsUnsupportedRecordType)
	}
}

func ZonesToAppliedZoneCandidates(zones []Zone) ([]networkmap.AppliedZoneCandidate, error) {
	toret := make([]networkmap.AppliedZoneCandidate, 0, len(zones))
	currentZoneId := ""
	for _, z := range zones {
		if !z.RecordType.Valid {
			continue
		}

		zone := nmdata.CustomZone{}
		err := FromSqlTypesToSharedTypes(
			reflect.ValueOf(&z), reflect.ValueOf(&zone))
		if err != nil {
			return nil, err
		}

		var distributionGroups []string
		if err := json.Unmarshal(z.DistributionGroups, &distributionGroups); err != nil {
			return nil, err
		}

		if z.Id != currentZoneId {
			// The account-side builder (types.buildAppliedZoneCandidates) states
			// the shape of an applied zone: names fully qualified, served
			// non-authoritatively. Both builders feed the same client-facing map,
			// so this one has to produce the same value.
			zone.Domain = dns.Fqdn(zone.Domain)
			zone.NonAuthoritative = true
			zone.Records = []nmdata.SimpleRecord{}
			toret = append(toret, AppliedZoneCandidateFromZone(zone, distributionGroups))
			currentZoneId = z.Id
		}

		rtype, rdata, err := RecordTypeAndRdata(z.RecordType.String, z.RecordRData.String)
		if err != nil {
			if errors.Is(err, ErrDnsUnsupportedRecordType) {
				continue
			}
			return nil, err
		}

		lastZone := &toret[len(toret)-1]
		lastZone.Zone.Records = append(lastZone.Zone.Records, nmdata.SimpleRecord{
			Name:  dns.Fqdn(z.RecordName.String),
			Class: z.RecordClass.String,
			TTL:   int(z.RecordTTL.Int64),
			RData: rdata,
			Type:  rtype,
		})
	}
	return toret, nil
}

func AppliedZoneCandidateFromZone(z nmdata.CustomZone, distributionGroups []string) networkmap.AppliedZoneCandidate {
	return networkmap.AppliedZoneCandidate{
		DistributionGroups: distributionGroups,
		Zone:               z,
	}
}

func ConvertToNmdataPeers(peers []Peer) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	toret := make([]nmdata.Peer, 0, len(peers))
	clusterToPeerIdx := make(map[string][]*nmdata.Peer)
	for _, p := range peers {
		dp := nmdata.Peer{}
		err := FromSqlTypesToSharedTypes(
			reflect.ValueOf(&p), reflect.ValueOf(&dp))
		if err != nil {
			return nil, nil, err
		}

		if p.ProxyMetaEmbedded.Valid {
			dp.ProxyMeta.Embedded = p.ProxyMetaEmbedded.Bool
		}
		dp.ProxyMeta.Cluster = p.ProxyMetaCluster.String
		// This is only used to build private service candidates, not connected peers are skipped
		dp.Connected = p.PeerStatusConnected.Bool
		if dp.ProxyMeta.Embedded && p.PeerStatusConnected.Bool {
			clusterToPeerIdx[p.ProxyMetaCluster.String] = append(clusterToPeerIdx[p.ProxyMetaCluster.String], &dp)
		}
		if p.MetaWtVersion.Valid {
			dp.Meta.WtVersion = p.MetaWtVersion.String
		}
		if p.MetaSyncMessageVersion.Valid {
			dp.Meta.SyncMessageVersion = int(p.MetaSyncMessageVersion.Int64)
		}
		if p.MetaGoOS.Valid {
			dp.Meta.GoOS = p.MetaGoOS.String
		}
		if p.MetaOSVersion.Valid {
			dp.Meta.OSVersion = p.MetaOSVersion.String
		}
		if p.MetaKernelVersion.Valid {
			dp.Meta.KernelVersion = p.MetaKernelVersion.String
		}
		if p.LocationCountryCode.Valid {
			dp.Location.CountryCode = p.LocationCountryCode.String
		}
		if p.LocationCityName.Valid {
			dp.Location.CityName = p.LocationCityName.String
		}
		if p.LocationConnectionIp != nil {
			err := json.Unmarshal(p.LocationConnectionIp, &dp.Location.ConnectionIP)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaFiles != nil {
			err := json.Unmarshal(p.MetaFiles, &dp.Meta.Files)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaCapabilities != nil {
			err := json.Unmarshal(p.MetaCapabilities, &dp.Meta.Capabilities)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaFlags != nil {
			err := json.Unmarshal(p.MetaFlags, &dp.Meta.Flags)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaNetworkAddresses != nil {
			err := json.Unmarshal(p.MetaNetworkAddresses, &dp.Meta.NetworkAddresses)
			if err != nil {
				return toret, nil, err
			}
		}

		toret = append(toret, dp)
	}

	return toret, clusterToPeerIdx, nil
}

func ConvertToNmdataPolicy(policies []Policy) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error) {
	toret := make([]nmdata.Policy, 0, len(policies))
	policyToDestinationResourceIdx := make(map[string]map[string]any) // policy id to destination resource id
	policyToDestinationGroupIdx := make(map[string]map[string]any)    // policy id to destination group id
	for _, p := range policies {
		policy, err := convertPolicyRow(p, policyToDestinationResourceIdx, policyToDestinationGroupIdx)
		if err != nil {
			return toret, nil, nil, err
		}
		toret = append(toret, policy)
	}

	return toret, policyToDestinationResourceIdx, policyToDestinationGroupIdx, nil
}

// convertPolicyRow turns one joined policy/rule row into an nmdata.Policy,
// recording the row's destination groups and resource in the two indexes.
//
// The join produces one row per rule, and a policy with no rules still has a
// row with every rule column NULL, so the rule is only attached when at least
// one of those columns carried a value.
func convertPolicyRow(p Policy, resourceIdx, groupIdx map[string]map[string]any) (nmdata.Policy, error) {
	policy := nmdata.Policy{}
	if err := FromSqlTypesToSharedTypes(reflect.ValueOf(&p), reflect.ValueOf(&policy)); err != nil {
		return nmdata.Policy{}, err
	}

	var policyRule *nmdata.PolicyRule
	pr := func() *nmdata.PolicyRule {
		if policyRule != nil {
			return policyRule
		}

		policyRule = &nmdata.PolicyRule{}
		return policyRule
	}

	if err := decodePolicyRuleColumns(p, pr, resourceIdx, groupIdx); err != nil {
		return nmdata.Policy{}, err
	}

	if policyRule != nil {
		policyRule.ID = p.ID
		policyRule.PolicyID = p.ID
		policy.Rules = []*nmdata.PolicyRule{policyRule}
	}
	return policy, nil
}

// decodePolicyRuleColumns reads the rule columns of a joined row onto the rule
// pr allocates on first use, and records the row's enabled destinations in the
// two indexes.
func decodePolicyRuleColumns(p Policy, pr func() *nmdata.PolicyRule, resourceIdx, groupIdx map[string]map[string]any) error {
	ruleEnabled := p.RuleEnabled.Valid && p.RuleEnabled.Bool

	for _, col := range []struct {
		raw    []byte
		target func() any
	}{
		{p.Sources, func() any { return &pr().Sources }},
		{p.Destinations, func() any { return &pr().Destinations }},
		{p.SourceResource, func() any { return &pr().SourceResource }},
		{p.DestinationResource, func() any { return &pr().DestinationResource }},
		{p.Ports, func() any { return &pr().Ports }},
		{p.PortRanges, func() any { return &pr().PortRanges }},
		{p.AuthorizedGroups, func() any { return &pr().AuthorizedGroups }},
	} {
		if len(col.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(col.raw, col.target()); err != nil {
			return err
		}
	}

	for _, col := range []struct {
		raw    sql.NullString
		target func() *string
	}{
		{p.Action, func() *string { return &pr().Action }},
		{p.Protocol, func() *string { return &pr().Protocol }},
		{p.AuthorizedUser, func() *string { return &pr().AuthorizedUser }},
		{p.SessionPubKey, func() *string { return &pr().SessionPubKey }},
		{p.SessionDisplayName, func() *string { return &pr().SessionDisplayName }},
	} {
		if col.raw.Valid {
			*col.target() = col.raw.String
		}
	}

	if p.RuleEnabled.Valid {
		pr().Enabled = p.RuleEnabled.Bool
	}
	if p.Bidirectional.Valid {
		pr().Bidirectional = p.Bidirectional.Bool
	}

	if !ruleEnabled {
		return nil
	}
	if len(p.Destinations) > 0 {
		for _, dst := range pr().Destinations {
			if _, ok := groupIdx[p.ID]; !ok {
				groupIdx[p.ID] = make(map[string]any)
			}
			groupIdx[p.ID][dst] = struct{}{}
		}
	}
	if len(p.DestinationResource) > 0 {
		if _, ok := resourceIdx[p.ID]; !ok {
			resourceIdx[p.ID] = make(map[string]any)
		}
		resourceIdx[p.ID][pr().DestinationResource.ID] = struct{}{}
	}
	return nil
}

// TwinProxyDomains converts registered reverse-proxy domain rows to their slim
// twins, so private-service zone apex resolution runs on the twin.
func TwinProxyDomains(domains []Domain) []nmdata.ProxyDomain {
	if len(domains) == 0 {
		return nil
	}
	out := make([]nmdata.ProxyDomain, 0, len(domains))
	for _, d := range domains {
		out = append(out, nmdata.ProxyDomain{Domain: d.Domain.String, TargetCluster: d.TargetCluster.String})
	}
	return out
}
