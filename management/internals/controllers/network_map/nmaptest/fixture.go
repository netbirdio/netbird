package nmaptest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// LoadNetworkMapData reads a fixture holding the NetworkMapData the store
// would return for one account. Unknown fields are rejected so fixture typos
// fail loudly instead of silently testing a default.
func LoadNetworkMapData(path string) (*networkmap.NetworkMapData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixture: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var nmData networkmap.NetworkMapData
	if err := dec.Decode(&nmData); err != nil {
		return nil, fmt.Errorf("decode fixture %s: %w", path, err)
	}
	return &nmData, nil
}

var defaultNetworkNet = func() net.IPNet {
	_, ipnet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err)
	}
	return *ipnet
}()

// applyFixtureDefaults fills the boilerplate a fixture may omit. Map-keyed
// objects inherit their key as ID, peers get a deterministic WG-shaped key
// and their ID as DNS label, PublicIDs default to the internal ID (the
// envelope encoder puts public IDs on the wire and silently degrades on
// empty ones), and a nil ValidatedPeers validates every peer — production
// fills it through the integrated validator, not the store.
func applyFixtureDefaults(nmData *networkmap.NetworkMapData) {
	if nmData.Network == nil {
		nmData.Network = &nmdata.Network{}
	}
	if nmData.Network.Identifier == "" {
		nmData.Network.Identifier = "network"
	}
	if nmData.Network.Net.IP == nil {
		nmData.Network.Net = defaultNetworkNet
	}
	if nmData.AccountSettings == nil {
		nmData.AccountSettings = &nmdata.AccountSettingsInfo{}
	}
	if nmData.DNSSettings == nil {
		nmData.DNSSettings = &nmdata.DNSSettings{}
	}

	for id, p := range nmData.Peers {
		if p == nil {
			continue
		}
		if p.ID == "" {
			p.ID = id
		}
		if p.Key == "" {
			p.Key = derivedWgKey(p.ID)
		}
		if p.DNSLabel == "" {
			p.DNSLabel = p.ID
		}
	}

	for id, g := range nmData.Groups {
		if g == nil {
			continue
		}
		if g.ID == "" {
			g.ID = id
		}
		if g.Name == "" {
			g.Name = g.ID
		}
		if g.PublicID == "" {
			g.PublicID = g.ID
		}
	}

	for _, policy := range nmData.Policies {
		defaultPolicyIDs(policy)
	}
	resolveResourcePolicyRefs(nmData)

	for _, r := range nmData.Routes {
		if r != nil && r.PublicID == "" {
			r.PublicID = r.ID
		}
	}
	for _, nsg := range nmData.NameServerGroups {
		if nsg != nil && nsg.PublicID == "" {
			nsg.PublicID = nsg.ID
		}
	}
	for _, res := range nmData.NetworkResources {
		if res == nil {
			continue
		}
		if res.PublicID == "" {
			res.PublicID = res.ID
		}
		defaultXIDMapping(&nmData.NetworkXIDToPublicID, res.NetworkID)
	}
	for networkID, routers := range nmData.Routers {
		defaultXIDMapping(&nmData.NetworkXIDToPublicID, networkID)
		for _, router := range routers {
			if router != nil && router.PublicID == "" {
				router.PublicID = networkID
			}
		}
	}

	for id, pc := range nmData.PostureChecks {
		if pc == nil {
			continue
		}
		if pc.ID == "" {
			pc.ID = id
		}
		defaultXIDMapping(&nmData.PostureCheckXIDToPublicID, pc.ID)
	}

	if nmData.ValidatedPeers == nil {
		nmData.ValidatedPeers = make(map[string]struct{}, len(nmData.Peers))
		for id := range nmData.Peers {
			nmData.ValidatedPeers[id] = struct{}{}
		}
	}
}

// resolveResourcePolicyRefs lets a fixture name an account policy by ID in
// ResourcePolicies — {"ID": "pol-x"} with no rules — instead of repeating it.
// The real store puts the same policy pointer in both places, which is what
// resolving the reference reproduces.
func resolveResourcePolicyRefs(nmData *networkmap.NetworkMapData) {
	byID := make(map[string]*nmdata.Policy, len(nmData.Policies))
	for _, policy := range nmData.Policies {
		if policy != nil && policy.ID != "" {
			byID[policy.ID] = policy
		}
	}

	for _, policies := range nmData.ResourcePolicies {
		for i, policy := range policies {
			if policy == nil {
				continue
			}
			if len(policy.Rules) == 0 {
				if full, ok := byID[policy.ID]; ok {
					policies[i] = full
					continue
				}
			}
			defaultPolicyIDs(policy)
		}
	}
}

func defaultPolicyIDs(policy *nmdata.Policy) {
	if policy == nil {
		return
	}
	if policy.PublicID == "" {
		policy.PublicID = policy.ID
	}
	for i, rule := range policy.Rules {
		if rule == nil {
			continue
		}
		if rule.PolicyID == "" {
			rule.PolicyID = policy.ID
		}
		if rule.ID == "" {
			// Production gives a rule its policy's id (management/server/policy.go:205,
			// "when policy can contain multiple rules, need refactor"), so a
			// single-rule policy — the only shape the product can create today —
			// must be modelled that way or the wire ids come out unrealistic.
			rule.ID = policy.ID
			if len(policy.Rules) > 1 {
				rule.ID = fmt.Sprintf("%s-rule-%d", policy.ID, i)
			}
		}
	}
}

func defaultXIDMapping(m *map[string]string, id string) {
	if id == "" {
		return
	}
	if *m == nil {
		*m = make(map[string]string)
	}
	if _, ok := (*m)[id]; !ok {
		(*m)[id] = id
	}
}

// derivedWgKey returns a deterministic base64 key of 32 bytes, valid for the
// envelope decoder's WG-key identity.
func derivedWgKey(peerID string) string {
	sum := sha256.Sum256([]byte(peerID))
	return base64.StdEncoding.EncodeToString(sum[:])
}
