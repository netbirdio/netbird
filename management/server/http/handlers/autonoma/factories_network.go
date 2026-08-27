package autonoma

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/http/api"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// GroupInput seeds a peer group. Peers named here are wired into the group as
// it is created, which is what produces the GroupPeer join rows.
type GroupInput struct {
	AccountID string   `json:"accountId"`
	Name      string   `json:"name"`
	Peers     []string `json:"peers,omitempty"`
}

func (f *factories) groupFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *GroupInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			group := &types.Group{
				Name:      in.Name,
				Peers:     strSlice(in.Peers),
				Resources: []types.Resource{},
				Issued:    types.GroupIssuedAPI,
			}
			if err := f.deps.AccountManager.CreateGroup(ctx, in.AccountID, actor, group); err != nil {
				return nil, fmt.Errorf("create group %q: %w", in.Name, err)
			}

			return map[string]any{"id": group.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeleteGroup(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// SetupKeyInput seeds an enrolment key.
type SetupKeyInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// Type is "reusable" or "one-off".
	Type string `json:"type"`
	// ExpiresInHours is an offset from seeding time because the product hides
	// and refuses expired keys; 0 means the key never expires.
	ExpiresInHours int      `json:"expiresInHours,omitempty"`
	AutoGroups     []string `json:"autoGroups,omitempty"`
	// UsageLimit is ignored for one-off keys, which are always capped at one.
	UsageLimit          int  `json:"usageLimit,omitempty"`
	Ephemeral           bool `json:"ephemeral,omitempty"`
	AllowExtraDNSLabels bool `json:"allowExtraDnsLabels,omitempty"`
}

func (f *factories) setupKeyFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *SetupKeyInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			keyType := types.SetupKeyType(orDefaultStr(in.Type, string(types.SetupKeyReusable)))
			usageLimit := in.UsageLimit
			if keyType == types.SetupKeyOneOff {
				usageLimit = 0
			}

			key, err := f.deps.AccountManager.CreateSetupKey(ctx, in.AccountID, in.Name, keyType,
				time.Duration(in.ExpiresInHours)*time.Hour, strSlice(in.AutoGroups), usageLimit, actor,
				in.Ephemeral, in.AllowExtraDNSLabels)
			if err != nil {
				return nil, fmt.Errorf("create setup key %q: %w", in.Name, err)
			}

			return map[string]any{
				"id":        key.Id,
				"accountId": in.AccountID,
				"name":      in.Name,
				"key":       key.Key,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeleteSetupKey(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// PeerInput registers a machine against the account, the way an agent enrolling
// with a user's credentials does. The WireGuard key is generated here: it is
// globally unique by construction, so concurrent runs never collide on it, and
// the IP and DNS label are allocated by the product from the account's network.
type PeerInput struct {
	AccountID string `json:"accountId"`
	// UserID owns the peer. With neither this nor SetupKey the peer is
	// registered by the account owner, which is how a peer the admin enrolled
	// on their own machine looks.
	UserID   string `json:"userId,omitempty"`
	SetupKey string `json:"setupKey,omitempty"`
	// Hostname becomes the peer name and the base of its DNS label.
	Hostname string `json:"hostname"`
	// GoOS is the runtime's OS id ("darwin", "linux", "windows", "android",
	// "ios"); OS and OSVersion are what posture checks read.
	GoOS      string `json:"goOs,omitempty"`
	OS        string `json:"os,omitempty"`
	OSVersion string `json:"osVersion,omitempty"`
	// Version is the agent version, which gates remote jobs and version checks.
	Version string `json:"version,omitempty"`
	// NetworkAddresses are the machine's local interface addresses, stored as
	// part of the peer's system metadata.
	NetworkAddresses []string `json:"networkAddresses,omitempty"`
	// Connected marks the peer as currently online.
	Connected bool `json:"connected,omitempty"`
	// LastSeenMinutesAgo is an offset from seeding time: the peer list renders
	// "last seen" relative to now, so a fixed timestamp would drift into
	// "months ago" within a week of writing the recipe.
	LastSeenMinutesAgo int `json:"lastSeenMinutesAgo,omitempty"`
}

func (f *factories) peerFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *PeerInput, fctx sdk.FactoryContext) (map[string]any, error) {
			userID := in.UserID
			if userID == "" && in.SetupKey == "" {
				owner, err := f.actorFor(ctx, fctx, in.AccountID)
				if err != nil {
					return nil, err
				}
				userID = owner
			}

			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return nil, fmt.Errorf("generate a WireGuard key: %w", err)
			}

			addresses := make([]nbpeer.NetworkAddress, 0, len(in.NetworkAddresses))
			for _, address := range in.NetworkAddresses {
				parsed, err := netip.ParsePrefix(address)
				if err != nil {
					return nil, fmt.Errorf("network address %q must be a prefix such as 192.168.1.50/24: %w", address, err)
				}
				addresses = append(addresses, nbpeer.NetworkAddress{NetIP: parsed})
			}

			peer := &nbpeer.Peer{
				Key: key.PublicKey().String(),
				Meta: nbpeer.PeerSystemMeta{
					Hostname:         in.Hostname,
					GoOS:             orDefaultStr(in.GoOS, "linux"),
					OS:               orDefaultStr(in.OS, "Ubuntu 24.04"),
					OSVersion:        orDefaultStr(in.OSVersion, "24.04"),
					Kernel:           "Linux",
					Core:             orDefaultStr(in.OSVersion, "24.04"),
					Platform:         "x86_64",
					WtVersion:        orDefaultStr(in.Version, "0.60.0"),
					NetworkAddresses: addresses,
				},
			}

			created, _, _, _, err := f.deps.AccountManager.AddPeer(ctx, in.AccountID, in.SetupKey, userID, peer, false)
			if err != nil {
				return nil, fmt.Errorf("add peer %q: %w", in.Hostname, err)
			}

			if in.Connected || in.LastSeenMinutesAgo > 0 {
				statusUpdate := nbpeer.PeerStatus{
					Connected: in.Connected,
					LastSeen:  minutesAgo(in.LastSeenMinutesAgo),
				}
				if in.Connected {
					statusUpdate.SessionStartedAt = time.Now().UTC().UnixNano()
				}
				if err := f.deps.Store.SavePeerStatus(ctx, in.AccountID, created.ID, statusUpdate); err != nil {
					return nil, fmt.Errorf("set the connection status of peer %q: %w", in.Hostname, err)
				}
			}

			return map[string]any{
				"id":        created.ID,
				"accountId": in.AccountID,
				"name":      created.Name,
				"ip":        created.IP.String(),
				"dnsLabel":  created.DNSLabel,
				"key":       created.Key,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeletePeer(ctx, accountID, str(record, "id"), owner)
		},
	)
}

// PolicyRuleInput is one rule inside a policy. Rules are written with their
// policy in a single transaction, so they have no factory of their own.
type PolicyRuleInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Action is "accept" or "drop".
	Action        string   `json:"action"`
	Sources       []string `json:"sources,omitempty"`
	Destinations  []string `json:"destinations,omitempty"`
	Bidirectional bool     `json:"bidirectional,omitempty"`
	// Protocol is "all", "tcp", "udp" or "icmp".
	Protocol string   `json:"protocol,omitempty"`
	Ports    []string `json:"ports,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
}

// PolicyInput seeds an access policy and its rules.
type PolicyInput struct {
	AccountID           string            `json:"accountId"`
	Name                string            `json:"name"`
	Description         string            `json:"description,omitempty"`
	Disabled            bool              `json:"disabled,omitempty"`
	Rules               []PolicyRuleInput `json:"rules"`
	SourcePostureChecks []string          `json:"sourcePostureChecks,omitempty"`
}

func (f *factories) policyFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *PolicyInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			rules := make([]*sharedtypes.PolicyRule, 0, len(in.Rules))
			for _, rule := range in.Rules {
				rules = append(rules, &sharedtypes.PolicyRule{
					Name:          rule.Name,
					Description:   rule.Description,
					Enabled:       !rule.Disabled,
					Action:        sharedtypes.PolicyTrafficActionType(orDefaultStr(rule.Action, "accept")),
					Sources:       strSlice(rule.Sources),
					Destinations:  strSlice(rule.Destinations),
					Bidirectional: rule.Bidirectional,
					Protocol:      sharedtypes.PolicyRuleProtocolType(orDefaultStr(rule.Protocol, "all")),
					Ports:         strSlice(rule.Ports),
				})
			}

			policy, err := f.deps.AccountManager.SavePolicy(ctx, in.AccountID, actor, &sharedtypes.Policy{
				AccountID:           in.AccountID,
				Name:                in.Name,
				Description:         in.Description,
				Enabled:             !in.Disabled,
				Rules:               rules,
				SourcePostureChecks: strSlice(in.SourcePostureChecks),
			}, true)
			if err != nil {
				return nil, fmt.Errorf("create policy %q: %w", in.Name, err)
			}

			return map[string]any{"id": policy.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeletePolicy(ctx, accountID, str(record, "id"), owner)
		},
	)
}

// ChecksInput seeds a posture check. Only the checks the input names are
// applied, so a scenario can seed an OS-version gate without inventing values
// for the geo or process checks.
type ChecksInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// MinAgentVersion gates peers on the NetBird agent version they run.
	MinAgentVersion string `json:"minAgentVersion,omitempty"`
	// MinDarwinVersion, MinLinuxKernelVersion and MinWindowsKernelVersion gate
	// peers on their operating system.
	MinDarwinVersion        string `json:"minDarwinVersion,omitempty"`
	MinLinuxKernelVersion   string `json:"minLinuxKernelVersion,omitempty"`
	MinWindowsKernelVersion string `json:"minWindowsKernelVersion,omitempty"`
}

func (f *factories) postureChecksFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ChecksInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			definition := posture.ChecksDefinition{}
			if in.MinAgentVersion != "" {
				definition.NBVersionCheck = &posture.NBVersionCheck{MinVersion: in.MinAgentVersion}
			}
			if in.MinDarwinVersion != "" || in.MinLinuxKernelVersion != "" || in.MinWindowsKernelVersion != "" {
				definition.OSVersionCheck = &posture.OSVersionCheck{}
				if in.MinDarwinVersion != "" {
					definition.OSVersionCheck.Darwin = &posture.MinVersionCheck{MinVersion: in.MinDarwinVersion}
				}
				if in.MinLinuxKernelVersion != "" {
					definition.OSVersionCheck.Linux = &posture.MinKernelVersionCheck{MinKernelVersion: in.MinLinuxKernelVersion}
				}
				if in.MinWindowsKernelVersion != "" {
					definition.OSVersionCheck.Windows = &posture.MinKernelVersionCheck{MinKernelVersion: in.MinWindowsKernelVersion}
				}
			}

			checks, err := f.deps.AccountManager.SavePostureChecks(ctx, in.AccountID, actor, &posture.Checks{
				Name:        in.Name,
				Description: in.Description,
				AccountID:   in.AccountID,
				Checks:      definition,
			}, true)
			if err != nil {
				return nil, fmt.Errorf("create posture check %q: %w", in.Name, err)
			}

			return map[string]any{"id": checks.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeletePostureChecks(ctx, accountID, str(record, "id"), owner)
		},
	)
}

// RouteInput publishes a network range or domain through a routing peer.
type RouteInput struct {
	AccountID string `json:"accountId"`
	// NetID is the route's short identifier, shown grouped in the UI. At most
	// 40 characters.
	NetID       string `json:"netId"`
	Description string `json:"description,omitempty"`
	// Network is a CIDR such as 172.20.0.0/16, or 0.0.0.0/0 for an exit node.
	Network string `json:"network"`
	// PeerID routes through a single peer; PeerGroups routes through a group.
	// Exactly one of the two.
	PeerID     string   `json:"peerId,omitempty"`
	PeerGroups []string `json:"peerGroups,omitempty"`
	// Groups are the peer groups the route is distributed to.
	Groups     []string `json:"groups"`
	Masquerade bool     `json:"masquerade,omitempty"`
	Metric     int      `json:"metric,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
	KeepRoute  bool     `json:"keepRoute,omitempty"`
}

func (f *factories) routeFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *RouteInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			prefix, err := netip.ParsePrefix(in.Network)
			if err != nil {
				return nil, fmt.Errorf("network %q must be a CIDR: %w", in.Network, err)
			}

			networkType := route.IPv4Network
			if prefix.Addr().Is6() {
				networkType = route.IPv6Network
			}

			created, err := f.deps.AccountManager.CreateRoute(ctx, in.AccountID, prefix, networkType, nil,
				in.PeerID, strSlice(in.PeerGroups), in.Description, route.NetID(in.NetID), in.Masquerade,
				orDefaultInt(in.Metric, 9999), strSlice(in.Groups), []string{}, !in.Disabled, actor, in.KeepRoute, false)
			if err != nil {
				return nil, fmt.Errorf("create route %q: %w", in.NetID, err)
			}

			return map[string]any{"id": string(created.ID), "accountId": in.AccountID, "netId": in.NetID}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeleteRoute(ctx, accountID, route.ID(str(record, "id")), owner)
		},
	)
}

// NameServerGroupInput seeds a DNS resolver set.
type NameServerGroupInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Nameservers are plain IPs; they are resolved over UDP on port 53.
	Nameservers []string `json:"nameservers"`
	Groups      []string `json:"groups"`
	// Primary makes the group answer every query rather than only the domains
	// listed below; the two are mutually exclusive.
	Primary              bool     `json:"primary,omitempty"`
	Domains              []string `json:"domains,omitempty"`
	Disabled             bool     `json:"disabled,omitempty"`
	SearchDomainsEnabled bool     `json:"searchDomainsEnabled,omitempty"`
}

func (f *factories) nameServerGroupFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *NameServerGroupInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			servers := make([]nbdns.NameServer, 0, len(in.Nameservers))
			for _, address := range in.Nameservers {
				ip, err := netip.ParseAddr(address)
				if err != nil {
					return nil, fmt.Errorf("nameserver %q must be an IP address: %w", address, err)
				}
				servers = append(servers, nbdns.NameServer{IP: ip, NSType: nbdns.UDPNameServerType, Port: nbdns.DefaultDNSPort})
			}

			created, err := f.deps.AccountManager.CreateNameServerGroup(ctx, in.AccountID, in.Name, in.Description,
				servers, strSlice(in.Groups), in.Primary, strSlice(in.Domains), !in.Disabled, actor, in.SearchDomainsEnabled)
			if err != nil {
				return nil, fmt.Errorf("create nameserver group %q: %w", in.Name, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeleteNameServerGroup(ctx, accountID, str(record, "id"), owner)
		},
	)
}

// NetworkInput seeds a network in the Networks feature - the container routers
// and resources hang off. It is distinct from the account's own IP network,
// which is created with the account and needs no factory.
type NetworkInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (f *factories) networkFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *NetworkInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			created, err := f.deps.NetworksManager.CreateNetwork(ctx, actor, &networkTypes.Network{
				AccountID:   in.AccountID,
				Name:        in.Name,
				Description: in.Description,
			})
			if err != nil {
				return nil, fmt.Errorf("create network %q: %w", in.Name, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.NetworksManager.DeleteNetwork(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// NetworkRouterInput attaches a routing peer to a network.
type NetworkRouterInput struct {
	AccountID  string   `json:"accountId"`
	NetworkID  string   `json:"networkId"`
	PeerID     string   `json:"peerId,omitempty"`
	PeerGroups []string `json:"peerGroups,omitempty"`
	Masquerade bool     `json:"masquerade,omitempty"`
	Metric     int      `json:"metric,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
}

func (f *factories) networkRouterFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *NetworkRouterInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			created, err := f.deps.RoutersManager.CreateRouter(ctx, actor, &routerTypes.NetworkRouter{
				NetworkID:  in.NetworkID,
				AccountID:  in.AccountID,
				Peer:       in.PeerID,
				PeerGroups: strSlice(in.PeerGroups),
				Masquerade: in.Masquerade,
				Metric:     orDefaultInt(in.Metric, 9999),
				Enabled:    !in.Disabled,
			})
			if err != nil {
				return nil, fmt.Errorf("create network router: %w", err)
			}

			return map[string]any{
				"id":        created.ID,
				"accountId": in.AccountID,
				"networkId": in.NetworkID,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.RoutersManager.DeleteRouter(ctx, accountID, owner, str(record, "networkId"), str(record, "id"))
		},
	)
}

// NetworkResourceInput publishes one address inside a network.
type NetworkResourceInput struct {
	AccountID   string `json:"accountId"`
	NetworkID   string `json:"networkId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Address is a host IP, a CIDR, or a domain - the product derives the
	// resource type from its shape.
	Address  string   `json:"address"`
	GroupIDs []string `json:"groupIds"`
	Disabled bool     `json:"disabled,omitempty"`
}

func (f *factories) networkResourceFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *NetworkResourceInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			created, err := f.deps.ResourcesManager.CreateResource(ctx, actor, &resourceTypes.NetworkResource{
				NetworkID:   in.NetworkID,
				AccountID:   in.AccountID,
				Name:        in.Name,
				Description: in.Description,
				Address:     in.Address,
				GroupIDs:    strSlice(in.GroupIDs),
				Enabled:     !in.Disabled,
			})
			if err != nil {
				return nil, fmt.Errorf("create network resource %q: %w", in.Name, err)
			}

			return map[string]any{
				"id":        created.ID,
				"accountId": in.AccountID,
				"networkId": in.NetworkID,
				"name":      in.Name,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.ResourcesManager.DeleteResource(ctx, accountID, owner, str(record, "networkId"), str(record, "id"))
		},
	)
}

// JobInput seeds a remote job against a peer - a debug bundle request and its
// outcome, as the peer list shows them.
//
// This is the one factory that cannot go through its manager: CreatePeerJob
// refuses a peer that has no live gRPC stream and pushes the job down that
// stream before persisting it, and a seeded peer has no agent behind it. The
// row is therefore written with the same store call the manager's transaction
// makes, and the side effect that is skipped is exactly that push.
type JobInput struct {
	AccountID string `json:"accountId"`
	PeerID    string `json:"peerId"`
	// TriggeredBy is the user id that asked for the job; empty means the
	// account owner did.
	TriggeredBy string `json:"triggeredBy,omitempty"`
	// Status is "pending", "succeeded" or "failed".
	Status string `json:"status,omitempty"`
	// Anonymize and LogFileCount are the bundle's own parameters, the ones the
	// troubleshooting screen offers. LogFileCount is between 1 and 1000.
	Anonymize    bool `json:"anonymize,omitempty"`
	LogFileCount int  `json:"logFileCount,omitempty"`
	// CreatedMinutesAgo is an offset from seeding time; the job list is
	// ordered and read relative to now.
	CreatedMinutesAgo int    `json:"createdMinutesAgo,omitempty"`
	FailedReason      string `json:"failedReason,omitempty"`
}

func (f *factories) jobFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *JobInput, fctx sdk.FactoryContext) (map[string]any, error) {
			triggeredBy := in.TriggeredBy
			if triggeredBy == "" {
				owner, err := f.actorFor(ctx, fctx, in.AccountID)
				if err != nil {
					return nil, err
				}
				triggeredBy = owner
			}

			// NewJob is the product's own constructor: it validates the bundle
			// parameters and fills in the workload the job list renders from.
			// Only the fields a live run would have written afterwards - when
			// it was asked for, and how it ended - are set on top.
			var workload api.WorkloadRequest
			if err := workload.FromBundleWorkloadRequest(api.BundleWorkloadRequest{
				Type: api.WorkloadTypeBundle,
				Parameters: api.BundleParameters{
					Anonymize:    in.Anonymize,
					LogFileCount: orDefaultInt(in.LogFileCount, 5),
				},
			}); err != nil {
				return nil, fmt.Errorf("build the bundle workload: %w", err)
			}

			job, err := types.NewJob(triggeredBy, in.AccountID, in.PeerID, &api.JobRequest{Workload: workload})
			if err != nil {
				return nil, fmt.Errorf("build peer job: %w", err)
			}

			createdAt := minutesAgo(in.CreatedMinutesAgo)
			job.CreatedAt = createdAt
			job.Status = types.JobStatus(orDefaultStr(in.Status, string(types.JobStatusPending)))
			job.FailedReason = in.FailedReason
			if job.Status != types.JobStatusPending {
				completedAt := createdAt.Add(time.Minute)
				job.CompletedAt = &completedAt
			}

			if err := f.deps.Store.CreatePeerJob(ctx, job); err != nil {
				return nil, fmt.Errorf("create peer job: %w", err)
			}

			return map[string]any{"id": job.ID, "accountId": in.AccountID, "peerId": in.PeerID}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			return f.cleaner.DeletePeerJobForTestData(ctx, str(record, "accountId"), str(record, "id"))
		},
	)
}

// ZoneInput seeds a private DNS zone.
type ZoneInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// Domain is the zone's suffix, for example acme.internal.
	Domain string `json:"domain"`
	// DistributionGroups are the peer groups the zone is served to; at least
	// one is required.
	DistributionGroups []string `json:"distributionGroups"`
	Disabled           bool     `json:"disabled,omitempty"`
	EnableSearchDomain bool     `json:"enableSearchDomain,omitempty"`
}

func (f *factories) zoneFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ZoneInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			created, err := f.deps.ZonesManager.CreateZone(ctx, in.AccountID, actor, &zones.Zone{
				AccountID:          in.AccountID,
				Name:               in.Name,
				Domain:             in.Domain,
				Enabled:            !in.Disabled,
				EnableSearchDomain: in.EnableSearchDomain,
				DistributionGroups: strSlice(in.DistributionGroups),
			})
			if err != nil {
				return nil, fmt.Errorf("create DNS zone %q: %w", in.Domain, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "domain": in.Domain}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.ZonesManager.DeleteZone(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// RecordInput seeds one DNS record inside a zone.
type RecordInput struct {
	AccountID string `json:"accountId"`
	ZoneID    string `json:"zoneId"`
	Name      string `json:"name"`
	// Type is "A", "AAAA" or "CNAME".
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

func (f *factories) recordFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *RecordInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			created, err := f.deps.RecordsManager.CreateRecord(ctx, in.AccountID, actor, in.ZoneID, &records.Record{
				AccountID: in.AccountID,
				ZoneID:    in.ZoneID,
				Name:      in.Name,
				Type:      records.RecordType(in.Type),
				Content:   in.Content,
				TTL:       orDefaultInt(in.TTL, 300),
			})
			if err != nil {
				return nil, fmt.Errorf("create DNS record %q: %w", in.Name, err)
			}

			return map[string]any{
				"id":        created.ID,
				"accountId": in.AccountID,
				"zoneId":    in.ZoneID,
				"name":      in.Name,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.RecordsManager.DeleteRecord(ctx, accountID, owner, str(record, "zoneId"), str(record, "id"))
		},
	)
}
