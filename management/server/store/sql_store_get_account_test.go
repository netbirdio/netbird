package store

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/integration_reference"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// TestGetAccount_ComprehensiveFieldValidation validates that GetAccount properly loads
// all fields and nested objects from the database, including deeply nested structures.
func TestGetAccount_ComprehensiveFieldValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping comprehensive test in short mode")
	}

	ctx := context.Background()
	store, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	// Create comprehensive test data
	accountID := "test-account-comprehensive"
	userID1 := "user-1"
	userID2 := "user-2"
	peerID1 := "peer-1"
	peerID2 := "peer-2"
	peerID3 := "peer-3"
	groupID1 := "group-1"
	groupID2 := "group-2"
	setupKeyID1 := "setup-key-1"
	setupKeyID2 := "setup-key-2"
	routeID1 := route.ID("route-1")
	routeID2 := route.ID("route-2")
	nsGroupID1 := "ns-group-1"
	nsGroupID2 := "ns-group-2"
	policyID1 := "policy-1"
	policyID2 := "policy-2"
	postureCheckID1 := "posture-check-1"
	postureCheckID2 := "posture-check-2"
	networkID1 := "network-1"
	routerID1 := "router-1"
	resourceID1 := "resource-1"
	patID1 := "pat-1"
	patID2 := "pat-2"
	patID3 := "pat-3"

	now := time.Now().UTC().Truncate(time.Second)
	lastLogin := now.Add(-24 * time.Hour)
	patLastUsed := now.Add(-1 * time.Hour)

	// Build comprehensive account with all fields populated
	account := &types.Account{
		Id:                     accountID,
		CreatedBy:              userID1,
		CreatedAt:              now,
		Domain:                 "example.com",
		DomainCategory:         "business",
		IsDomainPrimaryAccount: true,
		Network: &types.Network{
			Identifier: "test-network",
			Net: net.IPNet{
				IP:   net.ParseIP("100.64.0.0"),
				Mask: net.CIDRMask(10, 32),
			},
			Dns:    "test-dns",
			Serial: 42,
		},
		DNSSettings: types.DNSSettings{
			DisabledManagementGroups: []string{"dns-group-1", "dns-group-2"},
		},
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        time.Hour * 24 * 30,
			GroupsPropagationEnabled:   true,
			JWTGroupsEnabled:           true,
			JWTGroupsClaimName:         "groups",
			JWTAllowGroups:             []string{"allowed-group-1", "allowed-group-2"},
			RegularUsersViewBlocked:    false,
			Extra: &types.ExtraSettings{
				PeerApprovalEnabled:       true,
				IntegratedValidatorGroups: []string{"validator-1"},
			},
		},
	}

	// Create Setup Keys with all fields
	setupKey1ExpiresAt := now.Add(30 * 24 * time.Hour)
	setupKey1LastUsed := now.Add(-2 * time.Hour)
	setupKey1 := &types.SetupKey{
		Id:         setupKeyID1,
		AccountID:  accountID,
		Key:        "setup-key-secret-1",
		Name:       "Setup Key 1",
		Type:       types.SetupKeyReusable,
		CreatedAt:  now,
		UpdatedAt:  now,
		ExpiresAt:  &setupKey1ExpiresAt,
		Revoked:    false,
		UsedTimes:  5,
		LastUsed:   &setupKey1LastUsed,
		AutoGroups: []string{groupID1, groupID2},
		UsageLimit: 100,
		Ephemeral:  false,
	}

	setupKey2ExpiresAt := now.Add(7 * 24 * time.Hour)
	setupKey2LastUsed := now.Add(-1 * time.Hour)
	setupKey2 := &types.SetupKey{
		Id:         setupKeyID2,
		AccountID:  accountID,
		Key:        "setup-key-secret-2",
		Name:       "Setup Key 2 (One-off)",
		Type:       types.SetupKeyOneOff,
		CreatedAt:  now,
		UpdatedAt:  now,
		ExpiresAt:  &setupKey2ExpiresAt,
		Revoked:    true,
		UsedTimes:  1,
		LastUsed:   &setupKey2LastUsed,
		AutoGroups: []string{},
		UsageLimit: 1,
		Ephemeral:  true,
	}

	account.SetupKeys = map[string]*types.SetupKey{
		setupKey1.Key: setupKey1,
		setupKey2.Key: setupKey2,
	}

	// Create Peers with comprehensive fields
	peer1 := &nbpeer.Peer{
		ID:        peerID1,
		AccountID: accountID,
		Key:       "peer-key-1-AAAA",
		Name:      "Peer 1",
		IP:        net.ParseIP("100.64.0.1"),
		Meta: nbpeer.PeerSystemMeta{
			Hostname:      "peer1.example.com",
			GoOS:          "linux",
			Kernel:        "5.15.0",
			Core:          "x86_64",
			Platform:      "ubuntu",
			OS:            "Ubuntu 22.04",
			WtVersion:     "0.24.0",
			UIVersion:     "0.24.0",
			KernelVersion: "5.15.0-78-generic",
			OSVersion:     "22.04",
			NetworkAddresses: []nbpeer.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/32"), Mac: "00:11:22:33:44:55"},
				{NetIP: netip.MustParsePrefix("10.0.0.5/32"), Mac: "00:11:22:33:44:66"},
			},
			SystemSerialNumber: "ABC123",
			SystemProductName:  "Server Model X",
			SystemManufacturer: "Dell Inc.",
		},
		Status: &nbpeer.PeerStatus{
			LastSeen:         now.Add(-5 * time.Minute),
			Connected:        true,
			LoginExpired:     false,
			RequiresApproval: false,
		},
		Location: nbpeer.Location{
			ConnectionIP: net.ParseIP("203.0.113.10"),
			CountryCode:  "US",
			CityName:     "San Francisco",
			GeoNameID:    5391959,
		},
		SSHEnabled:                  true,
		SSHKey:                      "ssh-rsa AAAAB3NzaC1...",
		UserID:                      userID1,
		LoginExpirationEnabled:      true,
		InactivityExpirationEnabled: false,
		DNSLabel:                    "peer1",
		CreatedAt:                   now.Add(-30 * 24 * time.Hour),
		Ephemeral:                   false,
	}

	peer2 := &nbpeer.Peer{
		ID:        peerID2,
		AccountID: accountID,
		Key:       "peer-key-2-BBBB",
		Name:      "Peer 2",
		IP:        net.ParseIP("100.64.0.2"),
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "peer2.example.com",
			GoOS:      "darwin",
			Kernel:    "22.0.0",
			Core:      "arm64",
			Platform:  "darwin",
			OS:        "macOS Ventura",
			WtVersion: "0.24.0",
			UIVersion: "0.24.0",
		},
		Status: &nbpeer.PeerStatus{
			LastSeen:         now.Add(-1 * time.Hour),
			Connected:        false,
			LoginExpired:     true,
			RequiresApproval: true,
		},
		Location: nbpeer.Location{
			ConnectionIP: net.ParseIP("198.51.100.20"),
			CountryCode:  "GB",
			CityName:     "London",
			GeoNameID:    2643743,
		},
		SSHEnabled:                  false,
		UserID:                      userID2,
		LoginExpirationEnabled:      false,
		InactivityExpirationEnabled: true,
		DNSLabel:                    "peer2",
		CreatedAt:                   now.Add(-15 * 24 * time.Hour),
		Ephemeral:                   false,
	}

	peer3 := &nbpeer.Peer{
		ID:        peerID3,
		AccountID: accountID,
		Key:       "peer-key-3-CCCC",
		Name:      "Peer 3 (Ephemeral)",
		IP:        net.ParseIP("100.64.0.3"),
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "peer3.example.com",
			GoOS:     "windows",
			Platform: "windows",
		},
		Status: &nbpeer.PeerStatus{
			LastSeen:  now.Add(-10 * time.Minute),
			Connected: true,
		},
		DNSLabel:  "peer3",
		CreatedAt: now.Add(-1 * time.Hour),
		Ephemeral: true,
	}

	account.Peers = map[string]*nbpeer.Peer{
		peerID1: peer1,
		peerID2: peer2,
		peerID3: peer3,
	}

	// Create Users with PATs
	pat1ExpirationDate := now.Add(90 * 24 * time.Hour)
	pat1 := &types.PersonalAccessToken{
		ID:             patID1,
		Name:           "PAT 1",
		HashedToken:    "hashed-token-1",
		ExpirationDate: &pat1ExpirationDate,
		CreatedAt:      now.Add(-10 * 24 * time.Hour),
		CreatedBy:      userID1,
		LastUsed:       &patLastUsed,
	}

	pat2ExpirationDate := now.Add(30 * 24 * time.Hour)
	pat2 := &types.PersonalAccessToken{
		ID:             patID2,
		Name:           "PAT 2",
		HashedToken:    "hashed-token-2",
		ExpirationDate: &pat2ExpirationDate,
		CreatedAt:      now.Add(-5 * 24 * time.Hour),
		CreatedBy:      userID1,
	}

	pat3ExpirationDate := now.Add(60 * 24 * time.Hour)
	pat3 := &types.PersonalAccessToken{
		ID:             patID3,
		Name:           "PAT 3",
		HashedToken:    "hashed-token-3",
		ExpirationDate: &pat3ExpirationDate,
		CreatedAt:      now.Add(-2 * 24 * time.Hour),
		CreatedBy:      userID2,
	}

	user1 := &types.User{
		Id:            userID1,
		AccountID:     accountID,
		Role:          types.UserRoleOwner,
		IsServiceUser: false,
		NonDeletable:  true,
		AutoGroups:    []string{groupID1},
		Issued:        types.UserIssuedAPI,
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              123,
			IntegrationType: "azure_ad",
		},
		CreatedAt: now.Add(-60 * 24 * time.Hour),
		LastLogin: &lastLogin,
		Blocked:   false,
		PATs: map[string]*types.PersonalAccessToken{
			patID1: pat1,
			patID2: pat2,
		},
	}

	user2 := &types.User{
		Id:            userID2,
		AccountID:     accountID,
		Role:          types.UserRoleAdmin,
		IsServiceUser: true,
		NonDeletable:  false,
		AutoGroups:    []string{groupID2},
		Issued:        types.UserIssuedIntegration,
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              456,
			IntegrationType: "google_workspace",
		},
		CreatedAt: now.Add(-30 * 24 * time.Hour),
		Blocked:   false,
		PATs: map[string]*types.PersonalAccessToken{
			patID3: pat3,
		},
	}

	account.Users = map[string]*types.User{
		userID1: user1,
		userID2: user2,
	}

	// Create Groups with peers and resources
	group1 := &types.Group{
		ID:        groupID1,
		AccountID: accountID,
		Name:      "Group 1",
		Issued:    types.GroupIssuedAPI,
		Peers:     []string{peerID1, peerID2},
		Resources: []types.Resource{
			{
				ID:   "resource-1",
				Type: types.ResourceTypeHost,
			},
		},
	}

	group2 := &types.Group{
		ID:        groupID2,
		AccountID: accountID,
		Name:      "Group 2",
		Issued:    types.GroupIssuedIntegration,
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              789,
			IntegrationType: "okta",
		},
		Peers:     []string{peerID3},
		Resources: []types.Resource{},
	}

	account.Groups = map[string]*types.Group{
		groupID1: group1,
		groupID2: group2,
	}

	// Create Policies with Rules
	policy1 := &types.Policy{
		ID:          policyID1,
		AccountID:   accountID,
		Name:        "Policy 1",
		Description: "Main access policy",
		Enabled:     true,
		Rules: []*types.PolicyRule{
			{
				ID:            "rule-1",
				PolicyID:      policyID1,
				Name:          "Rule 1",
				Description:   "Allow access",
				Enabled:       true,
				Action:        types.PolicyTrafficActionAccept,
				Bidirectional: true,
				Protocol:      types.PolicyRuleProtocolALL,
				Ports:         []string{},
				PortRanges:    []types.RulePortRange{},
				Sources:       []string{groupID1},
				Destinations:  []string{groupID2},
			},
			{
				ID:            "rule-2",
				PolicyID:      policyID1,
				Name:          "Rule 2",
				Description:   "Block traffic on specific ports",
				Enabled:       true,
				Action:        types.PolicyTrafficActionDrop,
				Bidirectional: false,
				Protocol:      types.PolicyRuleProtocolTCP,
				Ports:         []string{"22", "3389"},
				PortRanges: []types.RulePortRange{
					{Start: 8000, End: 8999},
				},
				Sources:      []string{groupID2},
				Destinations: []string{groupID1},
			},
		},
	}

	policy2 := &types.Policy{
		ID:          policyID2,
		AccountID:   accountID,
		Name:        "Policy 2",
		Description: "Secondary policy",
		Enabled:     false,
		Rules: []*types.PolicyRule{
			{
				ID:            "rule-3",
				PolicyID:      policyID2,
				Name:          "Rule 3",
				Description:   "UDP access",
				Enabled:       false,
				Action:        types.PolicyTrafficActionAccept,
				Bidirectional: true,
				Protocol:      types.PolicyRuleProtocolUDP,
				Ports:         []string{"53"},
				Sources:       []string{groupID1},
				Destinations:  []string{groupID1},
			},
		},
	}

	account.Policies = []*types.Policy{policy1, policy2}

	// Create Routes
	route1 := &route.Route{
		ID:                  routeID1,
		AccountID:           accountID,
		Network:             netip.MustParsePrefix("10.0.0.0/24"),
		NetworkType:         route.IPv4Network,
		Peer:                peerID1,
		PeerGroups:          []string{},
		Description:         "Route 1",
		NetID:               "net-id-1",
		Masquerade:          true,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{groupID1},
		AccessControlGroups: []string{groupID2},
	}

	route2 := &route.Route{
		ID:                  routeID2,
		AccountID:           accountID,
		Network:             netip.MustParsePrefix("192.168.1.0/24"),
		NetworkType:         route.IPv4Network,
		Peer:                "",
		PeerGroups:          []string{groupID2},
		Description:         "Route 2 (High Availability)",
		NetID:               "net-id-2",
		Masquerade:          false,
		Metric:              100,
		Enabled:             true,
		Groups:              []string{groupID1, groupID2},
		AccessControlGroups: []string{groupID1},
	}

	account.Routes = map[route.ID]*route.Route{
		routeID1: route1,
		routeID2: route2,
	}

	// Create NameServer Groups
	nsGroup1 := &nbdns.NameServerGroup{
		ID:          nsGroupID1,
		AccountID:   accountID,
		Name:        "NS Group 1",
		Description: "Primary nameservers",
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("8.8.8.8"),
				NSType: nbdns.UDPNameServerType,
				Port:   53,
			},
			{
				IP:     netip.MustParseAddr("8.8.4.4"),
				NSType: nbdns.UDPNameServerType,
				Port:   53,
			},
		},
		Groups:               []string{groupID1, groupID2},
		Domains:              []string{"example.com", "test.com"},
		Enabled:              true,
		Primary:              true,
		SearchDomainsEnabled: true,
	}

	nsGroup2 := &nbdns.NameServerGroup{
		ID:          nsGroupID2,
		AccountID:   accountID,
		Name:        "NS Group 2",
		Description: "Secondary nameservers",
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("1.1.1.1"),
				NSType: nbdns.UDPNameServerType,
				Port:   53,
			},
		},
		Groups:               []string{},
		Domains:              []string{},
		Enabled:              false,
		Primary:              false,
		SearchDomainsEnabled: false,
	}

	account.NameServerGroups = map[string]*nbdns.NameServerGroup{
		nsGroupID1: nsGroup1,
		nsGroupID2: nsGroup2,
	}

	// Create Posture Checks
	postureCheck1 := &posture.Checks{
		ID:          postureCheckID1,
		AccountID:   accountID,
		Name:        "Posture Check 1",
		Description: "OS version check",
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.24.0",
			},
			OSVersionCheck: &posture.OSVersionCheck{
				Ios: &posture.MinVersionCheck{
					MinVersion: "16.0",
				},
				Darwin: &posture.MinVersionCheck{
					MinVersion: "22.0.0",
				},
			},
		},
	}

	postureCheck2 := &posture.Checks{
		ID:          postureCheckID2,
		AccountID:   accountID,
		Name:        "Posture Check 2",
		Description: "Geo location check",
		Checks: posture.ChecksDefinition{
			GeoLocationCheck: &posture.GeoLocationCheck{
				Locations: []posture.Location{
					{
						CountryCode: "US",
						CityName:    "San Francisco",
					},
					{
						CountryCode: "GB",
						CityName:    "London",
					},
				},
				Action: "allow",
			},
			PeerNetworkRangeCheck: &posture.PeerNetworkRangeCheck{
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/16"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
				Action: "allow",
			},
		},
	}

	account.PostureChecks = []*posture.Checks{postureCheck1, postureCheck2}

	// Create Networks
	network1 := &networkTypes.Network{
		ID:          networkID1,
		AccountID:   accountID,
		Name:        "Network 1",
		Description: "Primary network",
	}

	account.Networks = []*networkTypes.Network{network1}

	// Create Network Routers
	router1 := &routerTypes.NetworkRouter{
		ID:         routerID1,
		AccountID:  accountID,
		NetworkID:  networkID1,
		Peer:       peerID1,
		PeerGroups: []string{},
		Masquerade: true,
		Metric:     100,
	}

	account.NetworkRouters = []*routerTypes.NetworkRouter{router1}

	// Create Network Resources
	resource1 := &resourceTypes.NetworkResource{
		ID:          resourceID1,
		AccountID:   accountID,
		NetworkID:   networkID1,
		Name:        "Resource 1",
		Description: "Web server",
		Prefix:      netip.MustParsePrefix("192.168.1.100/32"),
		Type:        resourceTypes.Host,
	}

	account.NetworkResources = []*resourceTypes.NetworkResource{resource1}

	// Create Onboarding
	account.Onboarding = types.AccountOnboarding{
		AccountID:             accountID,
		OnboardingFlowPending: true,
		SignupFormPending:     false,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	// Save the account to the database
	err = store.SaveAccount(ctx, account)
	require.NoError(t, err, "Failed to save comprehensive test account")

	// Retrieve the account from the database
	retrievedAccount, err := store.GetAccount(ctx, accountID)
	require.NoError(t, err, "Failed to retrieve account")
	require.NotNil(t, retrievedAccount, "Retrieved account should not be nil")

	// ========== VALIDATE TOP-LEVEL FIELDS ==========
	t.Run("TopLevelFields", func(t *testing.T) {
		assert.Equal(t, accountID, retrievedAccount.Id, "Account ID mismatch")
		assert.Equal(t, userID1, retrievedAccount.CreatedBy, "CreatedBy mismatch")
		assert.WithinDuration(t, now, retrievedAccount.CreatedAt, time.Second, "CreatedAt mismatch")
		assert.Equal(t, "example.com", retrievedAccount.Domain, "Domain mismatch")
		assert.Equal(t, "business", retrievedAccount.DomainCategory, "DomainCategory mismatch")
		assert.True(t, retrievedAccount.IsDomainPrimaryAccount, "IsDomainPrimaryAccount should be true")
	})

	// ========== VALIDATE EMBEDDED NETWORK ==========
	t.Run("EmbeddedNetwork", func(t *testing.T) {
		require.NotNil(t, retrievedAccount.Network, "Network should not be nil")
		assert.Equal(t, "test-network", retrievedAccount.Network.Identifier, "Network Identifier mismatch")
		assert.Equal(t, "test-dns", retrievedAccount.Network.Dns, "Network DNS mismatch")
		assert.Equal(t, uint64(42), retrievedAccount.Network.Serial, "Network Serial mismatch")

		expectedIP := net.ParseIP("100.64.0.0")
		assert.True(t, retrievedAccount.Network.Net.IP.Equal(expectedIP), "Network IP mismatch")
		expectedMask := net.CIDRMask(10, 32)
		assert.Equal(t, expectedMask, retrievedAccount.Network.Net.Mask, "Network Mask mismatch")
	})

	// ========== VALIDATE DNS SETTINGS ==========
	t.Run("DNSSettings", func(t *testing.T) {
		assert.Len(t, retrievedAccount.DNSSettings.DisabledManagementGroups, 2, "DisabledManagementGroups length mismatch")
		assert.Contains(t, retrievedAccount.DNSSettings.DisabledManagementGroups, "dns-group-1", "Missing dns-group-1")
		assert.Contains(t, retrievedAccount.DNSSettings.DisabledManagementGroups, "dns-group-2", "Missing dns-group-2")
	})

	// ========== VALIDATE SETTINGS ==========
	t.Run("Settings", func(t *testing.T) {
		require.NotNil(t, retrievedAccount.Settings, "Settings should not be nil")
		assert.True(t, retrievedAccount.Settings.PeerLoginExpirationEnabled, "PeerLoginExpirationEnabled mismatch")
		assert.Equal(t, time.Hour*24*30, retrievedAccount.Settings.PeerLoginExpiration, "PeerLoginExpiration mismatch")
		assert.True(t, retrievedAccount.Settings.GroupsPropagationEnabled, "GroupsPropagationEnabled mismatch")
		assert.True(t, retrievedAccount.Settings.JWTGroupsEnabled, "JWTGroupsEnabled mismatch")
		assert.Equal(t, "groups", retrievedAccount.Settings.JWTGroupsClaimName, "JWTGroupsClaimName mismatch")
		assert.Len(t, retrievedAccount.Settings.JWTAllowGroups, 2, "JWTAllowGroups length mismatch")
		assert.Contains(t, retrievedAccount.Settings.JWTAllowGroups, "allowed-group-1")
		assert.Contains(t, retrievedAccount.Settings.JWTAllowGroups, "allowed-group-2")
		assert.False(t, retrievedAccount.Settings.RegularUsersViewBlocked, "RegularUsersViewBlocked mismatch")

		// Validate Extra Settings
		require.NotNil(t, retrievedAccount.Settings.Extra, "Extra settings should not be nil")
		assert.True(t, retrievedAccount.Settings.Extra.PeerApprovalEnabled, "PeerApprovalEnabled mismatch")
		assert.Len(t, retrievedAccount.Settings.Extra.IntegratedValidatorGroups, 1, "IntegratedValidatorGroups length mismatch")
		assert.Equal(t, "validator-1", retrievedAccount.Settings.Extra.IntegratedValidatorGroups[0])
	})

	// ========== VALIDATE SETUP KEYS ==========
	t.Run("SetupKeys", func(t *testing.T) {
		require.Len(t, retrievedAccount.SetupKeys, 2, "Should have 2 setup keys")

		// Validate Setup Key 1
		sk1, exists := retrievedAccount.SetupKeys["setup-key-secret-1"]
		require.True(t, exists, "Setup key 1 should exist")
		assert.Equal(t, "Setup Key 1", sk1.Name, "Setup key 1 name mismatch")
		assert.Equal(t, types.SetupKeyReusable, sk1.Type, "Setup key 1 type mismatch")
		assert.False(t, sk1.Revoked, "Setup key 1 should not be revoked")
		assert.Equal(t, 5, sk1.UsedTimes, "Setup key 1 used times mismatch")
		assert.Equal(t, 100, sk1.UsageLimit, "Setup key 1 usage limit mismatch")
		assert.False(t, sk1.Ephemeral, "Setup key 1 should not be ephemeral")
		assert.Len(t, sk1.AutoGroups, 2, "Setup key 1 auto groups length mismatch")
		assert.Contains(t, sk1.AutoGroups, groupID1)
		assert.Contains(t, sk1.AutoGroups, groupID2)

		// Validate Setup Key 2
		sk2, exists := retrievedAccount.SetupKeys["setup-key-secret-2"]
		require.True(t, exists, "Setup key 2 should exist")
		assert.Equal(t, "Setup Key 2 (One-off)", sk2.Name, "Setup key 2 name mismatch")
		assert.Equal(t, types.SetupKeyOneOff, sk2.Type, "Setup key 2 type mismatch")
		assert.True(t, sk2.Revoked, "Setup key 2 should be revoked")
		assert.Equal(t, 1, sk2.UsedTimes, "Setup key 2 used times mismatch")
		assert.Equal(t, 1, sk2.UsageLimit, "Setup key 2 usage limit mismatch")
		assert.True(t, sk2.Ephemeral, "Setup key 2 should be ephemeral")
		assert.Len(t, sk2.AutoGroups, 0, "Setup key 2 should have empty auto groups")
	})

	// ========== VALIDATE PEERS ==========
	t.Run("Peers", func(t *testing.T) {
		require.Len(t, retrievedAccount.Peers, 3, "Should have 3 peers")

		// Validate Peer 1
		p1, exists := retrievedAccount.Peers[peerID1]
		require.True(t, exists, "Peer 1 should exist")
		assert.Equal(t, "Peer 1", p1.Name, "Peer 1 name mismatch")
		assert.Equal(t, "peer-key-1-AAAA", p1.Key, "Peer 1 key mismatch")
		assert.True(t, p1.IP.Equal(net.ParseIP("100.64.0.1")), "Peer 1 IP mismatch")
		assert.Equal(t, userID1, p1.UserID, "Peer 1 user ID mismatch")
		assert.True(t, p1.SSHEnabled, "Peer 1 SSH should be enabled")
		assert.Equal(t, "ssh-rsa AAAAB3NzaC1...", p1.SSHKey, "Peer 1 SSH key mismatch")
		assert.True(t, p1.LoginExpirationEnabled, "Peer 1 login expiration should be enabled")
		assert.False(t, p1.Ephemeral, "Peer 1 should not be ephemeral")
		assert.Equal(t, "peer1", p1.DNSLabel, "Peer 1 DNS label mismatch")

		// Validate Peer 1 Meta
		assert.Equal(t, "peer1.example.com", p1.Meta.Hostname, "Peer 1 hostname mismatch")
		assert.Equal(t, "linux", p1.Meta.GoOS, "Peer 1 OS mismatch")
		assert.Equal(t, "5.15.0", p1.Meta.Kernel, "Peer 1 kernel mismatch")
		assert.Equal(t, "x86_64", p1.Meta.Core, "Peer 1 core mismatch")
		assert.Equal(t, "ubuntu", p1.Meta.Platform, "Peer 1 platform mismatch")
		assert.Equal(t, "Ubuntu 22.04", p1.Meta.OS, "Peer 1 OS version mismatch")
		assert.Equal(t, "0.24.0", p1.Meta.WtVersion, "Peer 1 wt version mismatch")
		assert.Equal(t, "ABC123", p1.Meta.SystemSerialNumber, "Peer 1 serial number mismatch")
		assert.Equal(t, "Server Model X", p1.Meta.SystemProductName, "Peer 1 product name mismatch")
		assert.Equal(t, "Dell Inc.", p1.Meta.SystemManufacturer, "Peer 1 manufacturer mismatch")

		// Validate Network Addresses
		assert.Len(t, p1.Meta.NetworkAddresses, 2, "Peer 1 should have 2 network addresses")
		assert.Equal(t, netip.MustParsePrefix("192.168.1.10/32"), p1.Meta.NetworkAddresses[0].NetIP, "Network address 1 IP mismatch")
		assert.Equal(t, "00:11:22:33:44:55", p1.Meta.NetworkAddresses[0].Mac, "Network address 1 MAC mismatch")
		assert.Equal(t, netip.MustParsePrefix("10.0.0.5/32"), p1.Meta.NetworkAddresses[1].NetIP, "Network address 2 IP mismatch")
		assert.Equal(t, "00:11:22:33:44:66", p1.Meta.NetworkAddresses[1].Mac, "Network address 2 MAC mismatch")

		// Validate Peer 1 Status
		require.NotNil(t, p1.Status, "Peer 1 status should not be nil")
		assert.True(t, p1.Status.Connected, "Peer 1 should be connected")
		assert.False(t, p1.Status.LoginExpired, "Peer 1 login should not be expired")
		assert.False(t, p1.Status.RequiresApproval, "Peer 1 should not require approval")

		// Validate Peer 1 Location
		assert.True(t, p1.Location.ConnectionIP.Equal(net.ParseIP("203.0.113.10")), "Peer 1 connection IP mismatch")
		assert.Equal(t, "US", p1.Location.CountryCode, "Peer 1 country code mismatch")
		assert.Equal(t, "San Francisco", p1.Location.CityName, "Peer 1 city name mismatch")
		assert.Equal(t, uint(5391959), p1.Location.GeoNameID, "Peer 1 geo name ID mismatch")

		// Validate Peer 2
		p2, exists := retrievedAccount.Peers[peerID2]
		require.True(t, exists, "Peer 2 should exist")
		assert.Equal(t, "Peer 2", p2.Name, "Peer 2 name mismatch")
		assert.Equal(t, "peer-key-2-BBBB", p2.Key, "Peer 2 key mismatch")
		assert.False(t, p2.SSHEnabled, "Peer 2 SSH should be disabled")
		assert.False(t, p2.LoginExpirationEnabled, "Peer 2 login expiration should be disabled")
		assert.True(t, p2.InactivityExpirationEnabled, "Peer 2 inactivity expiration should be enabled")

		// Validate Peer 2 Status
		require.NotNil(t, p2.Status, "Peer 2 status should not be nil")
		assert.False(t, p2.Status.Connected, "Peer 2 should not be connected")
		assert.True(t, p2.Status.LoginExpired, "Peer 2 login should be expired")
		assert.True(t, p2.Status.RequiresApproval, "Peer 2 should require approval")

		// Validate Peer 3 (Ephemeral)
		p3, exists := retrievedAccount.Peers[peerID3]
		require.True(t, exists, "Peer 3 should exist")
		assert.True(t, p3.Ephemeral, "Peer 3 should be ephemeral")
		assert.Equal(t, "Peer 3 (Ephemeral)", p3.Name, "Peer 3 name mismatch")
	})

	// ========== VALIDATE USERS ==========
	t.Run("Users", func(t *testing.T) {
		require.Len(t, retrievedAccount.Users, 2, "Should have 2 users")

		// Validate User 1
		u1, exists := retrievedAccount.Users[userID1]
		require.True(t, exists, "User 1 should exist")
		assert.Equal(t, types.UserRoleOwner, u1.Role, "User 1 role mismatch")
		assert.False(t, u1.IsServiceUser, "User 1 should not be a service user")
		assert.True(t, u1.NonDeletable, "User 1 should be non-deletable")
		assert.Equal(t, types.UserIssuedAPI, u1.Issued, "User 1 issued type mismatch")
		assert.Len(t, u1.AutoGroups, 1, "User 1 auto groups length mismatch")
		assert.Contains(t, u1.AutoGroups, groupID1, "User 1 should have group1")
		assert.False(t, u1.Blocked, "User 1 should not be blocked")
		require.NotNil(t, u1.LastLogin, "User 1 last login should not be nil")
		assert.WithinDuration(t, lastLogin, *u1.LastLogin, time.Second, "User 1 last login mismatch")

		// Validate User 1 Integration Reference
		assert.Equal(t, 123, u1.IntegrationReference.ID, "User 1 integration ID mismatch")
		assert.Equal(t, "azure_ad", u1.IntegrationReference.IntegrationType, "User 1 integration type mismatch")

		// Validate User 1 PATs
		require.Len(t, u1.PATs, 2, "User 1 should have 2 PATs")

		pat1Retrieved, exists := u1.PATs[patID1]
		require.True(t, exists, "PAT 1 should exist")
		assert.Equal(t, "PAT 1", pat1Retrieved.Name, "PAT 1 name mismatch")
		assert.Equal(t, "hashed-token-1", pat1Retrieved.HashedToken, "PAT 1 hashed token mismatch")
		require.NotNil(t, pat1Retrieved.LastUsed, "PAT 1 last used should not be nil")
		assert.WithinDuration(t, patLastUsed, *pat1Retrieved.LastUsed, time.Second, "PAT 1 last used mismatch")
		assert.Equal(t, userID1, pat1Retrieved.CreatedBy, "PAT 1 created by mismatch")
		assert.Empty(t, pat1Retrieved.UserID, "PAT 1 UserID should be cleared")

		pat2Retrieved, exists := u1.PATs[patID2]
		require.True(t, exists, "PAT 2 should exist")
		assert.Equal(t, "PAT 2", pat2Retrieved.Name, "PAT 2 name mismatch")
		assert.Nil(t, pat2Retrieved.LastUsed, "PAT 2 last used should be nil")

		// Validate User 2
		u2, exists := retrievedAccount.Users[userID2]
		require.True(t, exists, "User 2 should exist")
		assert.Equal(t, types.UserRoleAdmin, u2.Role, "User 2 role mismatch")
		assert.True(t, u2.IsServiceUser, "User 2 should be a service user")
		assert.False(t, u2.NonDeletable, "User 2 should be deletable")
		assert.Equal(t, types.UserIssuedIntegration, u2.Issued, "User 2 issued type mismatch")
		assert.Equal(t, "google_workspace", u2.IntegrationReference.IntegrationType, "User 2 integration type mismatch")

		// Validate User 2 PATs
		require.Len(t, u2.PATs, 1, "User 2 should have 1 PAT")
		pat3Retrieved, exists := u2.PATs[patID3]
		require.True(t, exists, "PAT 3 should exist")
		assert.Equal(t, "PAT 3", pat3Retrieved.Name, "PAT 3 name mismatch")
	})

	// ========== VALIDATE GROUPS ==========
	t.Run("Groups", func(t *testing.T) {
		require.Len(t, retrievedAccount.Groups, 2, "Should have 2 groups")

		// Validate Group 1
		g1, exists := retrievedAccount.Groups[groupID1]
		require.True(t, exists, "Group 1 should exist")
		assert.Equal(t, "Group 1", g1.Name, "Group 1 name mismatch")
		assert.Equal(t, types.GroupIssuedAPI, g1.Issued, "Group 1 issued type mismatch")
		assert.Len(t, g1.Peers, 2, "Group 1 should have 2 peers")
		assert.Contains(t, g1.Peers, peerID1, "Group 1 should contain peer 1")
		assert.Contains(t, g1.Peers, peerID2, "Group 1 should contain peer 2")

		// Validate Group 1 Resources
		assert.Len(t, g1.Resources, 1, "Group 1 should have 1 resource")
		assert.Equal(t, "resource-1", g1.Resources[0].ID, "Group 1 resource ID mismatch")
		assert.Equal(t, types.ResourceTypeHost, g1.Resources[0].Type, "Group 1 resource type mismatch")

		// Validate Group 2
		g2, exists := retrievedAccount.Groups[groupID2]
		require.True(t, exists, "Group 2 should exist")
		assert.Equal(t, "Group 2", g2.Name, "Group 2 name mismatch")
		assert.Equal(t, types.GroupIssuedIntegration, g2.Issued, "Group 2 issued type mismatch")
		assert.Len(t, g2.Peers, 1, "Group 2 should have 1 peer")
		assert.Contains(t, g2.Peers, peerID3, "Group 2 should contain peer 3")
		assert.Len(t, g2.Resources, 0, "Group 2 should have 0 resources")

		// Validate Group 2 Integration Reference
		assert.Equal(t, 789, g2.IntegrationReference.ID, "Group 2 integration ID mismatch")
		assert.Equal(t, "okta", g2.IntegrationReference.IntegrationType, "Group 2 integration type mismatch")
	})

	// ========== VALIDATE POLICIES ==========
	t.Run("Policies", func(t *testing.T) {
		require.Len(t, retrievedAccount.Policies, 2, "Should have 2 policies")

		// Validate Policy 1
		pol1 := retrievedAccount.Policies[0]
		if pol1.ID != policyID1 {
			pol1 = retrievedAccount.Policies[1]
		}
		assert.Equal(t, policyID1, pol1.ID, "Policy 1 ID mismatch")
		assert.Equal(t, "Policy 1", pol1.Name, "Policy 1 name mismatch")
		assert.Equal(t, "Main access policy", pol1.Description, "Policy 1 description mismatch")
		assert.True(t, pol1.Enabled, "Policy 1 should be enabled")

		// Validate Policy 1 Rules
		require.Len(t, pol1.Rules, 2, "Policy 1 should have 2 rules")

		rule1 := pol1.Rules[0]
		assert.Equal(t, "Rule 1", rule1.Name, "Rule 1 name mismatch")
		assert.Equal(t, "Allow access", rule1.Description, "Rule 1 description mismatch")
		assert.True(t, rule1.Enabled, "Rule 1 should be enabled")
		assert.Equal(t, types.PolicyTrafficActionAccept, rule1.Action, "Rule 1 action mismatch")
		assert.True(t, rule1.Bidirectional, "Rule 1 should be bidirectional")
		assert.Equal(t, types.PolicyRuleProtocolALL, rule1.Protocol, "Rule 1 protocol mismatch")
		assert.Len(t, rule1.Sources, 1, "Rule 1 sources length mismatch")
		assert.Contains(t, rule1.Sources, groupID1, "Rule 1 should have group1 as source")
		assert.Len(t, rule1.Destinations, 1, "Rule 1 destinations length mismatch")
		assert.Contains(t, rule1.Destinations, groupID2, "Rule 1 should have group2 as destination")

		rule2 := pol1.Rules[1]
		assert.Equal(t, "Rule 2", rule2.Name, "Rule 2 name mismatch")
		assert.Equal(t, types.PolicyTrafficActionDrop, rule2.Action, "Rule 2 action mismatch")
		assert.False(t, rule2.Bidirectional, "Rule 2 should not be bidirectional")
		assert.Equal(t, types.PolicyRuleProtocolTCP, rule2.Protocol, "Rule 2 protocol mismatch")
		assert.Len(t, rule2.Ports, 2, "Rule 2 ports length mismatch")
		assert.Contains(t, rule2.Ports, "22", "Rule 2 should have port 22")
		assert.Contains(t, rule2.Ports, "3389", "Rule 2 should have port 3389")
		assert.Len(t, rule2.PortRanges, 1, "Rule 2 port ranges length mismatch")
		assert.Equal(t, uint16(8000), rule2.PortRanges[0].Start, "Rule 2 port range start mismatch")
		assert.Equal(t, uint16(8999), rule2.PortRanges[0].End, "Rule 2 port range end mismatch")

		// Validate Policy 2
		pol2 := retrievedAccount.Policies[1]
		if pol2.ID != policyID2 {
			pol2 = retrievedAccount.Policies[0]
		}
		assert.Equal(t, policyID2, pol2.ID, "Policy 2 ID mismatch")
		assert.Equal(t, "Policy 2", pol2.Name, "Policy 2 name mismatch")
		assert.False(t, pol2.Enabled, "Policy 2 should be disabled")
		require.Len(t, pol2.Rules, 1, "Policy 2 should have 1 rule")

		rule3 := pol2.Rules[0]
		assert.Equal(t, "Rule 3", rule3.Name, "Rule 3 name mismatch")
		assert.False(t, rule3.Enabled, "Rule 3 should be disabled")
		assert.Equal(t, types.PolicyRuleProtocolUDP, rule3.Protocol, "Rule 3 protocol mismatch")
	})

	// ========== VALIDATE ROUTES ==========
	t.Run("Routes", func(t *testing.T) {
		require.Len(t, retrievedAccount.Routes, 2, "Should have 2 routes")

		// Validate Route 1
		r1, exists := retrievedAccount.Routes[routeID1]
		require.True(t, exists, "Route 1 should exist")
		assert.Equal(t, "Route 1", r1.Description, "Route 1 description mismatch")
		assert.Equal(t, route.IPv4Network, r1.NetworkType, "Route 1 network type mismatch")
		assert.Equal(t, peerID1, r1.Peer, "Route 1 peer mismatch")
		assert.Empty(t, r1.PeerGroups, "Route 1 peer groups should be empty")
		assert.Equal(t, route.NetID("net-id-1"), r1.NetID, "Route 1 net ID mismatch")
		assert.True(t, r1.Masquerade, "Route 1 masquerade should be enabled")
		assert.Equal(t, 9999, r1.Metric, "Route 1 metric mismatch")
		assert.True(t, r1.Enabled, "Route 1 should be enabled")
		assert.Len(t, r1.Groups, 1, "Route 1 groups length mismatch")
		assert.Contains(t, r1.Groups, groupID1, "Route 1 should have group1")
		assert.Len(t, r1.AccessControlGroups, 1, "Route 1 ACL groups length mismatch")
		assert.Contains(t, r1.AccessControlGroups, groupID2, "Route 1 should have group2 in ACL")

		// Validate Route 1 Network CIDR
		assert.Equal(t, "10.0.0.0/24", r1.Network.String(), "Route 1 network CIDR mismatch")

		// Validate Route 2
		r2, exists := retrievedAccount.Routes[routeID2]
		require.True(t, exists, "Route 2 should exist")
		assert.Equal(t, "Route 2 (High Availability)", r2.Description, "Route 2 description mismatch")
		assert.Empty(t, r2.Peer, "Route 2 peer should be empty")
		assert.Len(t, r2.PeerGroups, 1, "Route 2 peer groups length mismatch")
		assert.Contains(t, r2.PeerGroups, groupID2, "Route 2 should have group2 as peer group")
		assert.False(t, r2.Masquerade, "Route 2 masquerade should be disabled")
		assert.Equal(t, 100, r2.Metric, "Route 2 metric mismatch")
		assert.Equal(t, "192.168.1.0/24", r2.Network.String(), "Route 2 network CIDR mismatch")
	})

	// ========== VALIDATE NAME SERVER GROUPS ==========
	t.Run("NameServerGroups", func(t *testing.T) {
		require.Len(t, retrievedAccount.NameServerGroups, 2, "Should have 2 nameserver groups")

		// Validate NS Group 1
		nsg1, exists := retrievedAccount.NameServerGroups[nsGroupID1]
		require.True(t, exists, "NS Group 1 should exist")
		assert.Equal(t, "NS Group 1", nsg1.Name, "NS Group 1 name mismatch")
		assert.Equal(t, "Primary nameservers", nsg1.Description, "NS Group 1 description mismatch")
		assert.True(t, nsg1.Enabled, "NS Group 1 should be enabled")
		assert.True(t, nsg1.Primary, "NS Group 1 should be primary")
		assert.True(t, nsg1.SearchDomainsEnabled, "NS Group 1 search domains should be enabled")
		assert.Empty(t, nsg1.AccountID, "NS Group 1 AccountID should be cleared")

		// Validate NS Group 1 NameServers
		require.Len(t, nsg1.NameServers, 2, "NS Group 1 should have 2 nameservers")
		assert.Equal(t, netip.MustParseAddr("8.8.8.8"), nsg1.NameServers[0].IP, "NS Group 1 nameserver 1 IP mismatch")
		assert.Equal(t, nbdns.UDPNameServerType, nsg1.NameServers[0].NSType, "NS Group 1 nameserver 1 type mismatch")
		assert.Equal(t, 53, nsg1.NameServers[0].Port, "NS Group 1 nameserver 1 port mismatch")
		assert.Equal(t, netip.MustParseAddr("8.8.4.4"), nsg1.NameServers[1].IP, "NS Group 1 nameserver 2 IP mismatch")

		// Validate NS Group 1 Groups and Domains
		assert.Len(t, nsg1.Groups, 2, "NS Group 1 groups length mismatch")
		assert.Contains(t, nsg1.Groups, groupID1, "NS Group 1 should have group1")
		assert.Contains(t, nsg1.Groups, groupID2, "NS Group 1 should have group2")
		assert.Len(t, nsg1.Domains, 2, "NS Group 1 domains length mismatch")
		assert.Contains(t, nsg1.Domains, "example.com", "NS Group 1 should have example.com domain")
		assert.Contains(t, nsg1.Domains, "test.com", "NS Group 1 should have test.com domain")

		// Validate NS Group 2
		nsg2, exists := retrievedAccount.NameServerGroups[nsGroupID2]
		require.True(t, exists, "NS Group 2 should exist")
		assert.Equal(t, "NS Group 2", nsg2.Name, "NS Group 2 name mismatch")
		assert.False(t, nsg2.Enabled, "NS Group 2 should be disabled")
		assert.False(t, nsg2.Primary, "NS Group 2 should not be primary")
		assert.False(t, nsg2.SearchDomainsEnabled, "NS Group 2 search domains should be disabled")
		assert.Len(t, nsg2.NameServers, 1, "NS Group 2 should have 1 nameserver")
		assert.Len(t, nsg2.Groups, 0, "NS Group 2 should have empty groups")
		assert.Len(t, nsg2.Domains, 0, "NS Group 2 should have empty domains")
	})

	// ========== VALIDATE POSTURE CHECKS ==========
	t.Run("PostureChecks", func(t *testing.T) {
		require.Len(t, retrievedAccount.PostureChecks, 2, "Should have 2 posture checks")

		// Find posture checks by ID
		var pc1, pc2 *posture.Checks
		for _, pc := range retrievedAccount.PostureChecks {
			switch pc.ID {
			case postureCheckID1:
				pc1 = pc
			case postureCheckID2:
				pc2 = pc
			}
		}

		// Validate Posture Check 1
		require.NotNil(t, pc1, "Posture check 1 should exist")
		assert.Equal(t, "Posture Check 1", pc1.Name, "Posture check 1 name mismatch")
		assert.Equal(t, "OS version check", pc1.Description, "Posture check 1 description mismatch")

		// Validate NB Version Check
		require.NotNil(t, pc1.Checks.NBVersionCheck, "NB version check should not be nil")
		assert.Equal(t, "0.24.0", pc1.Checks.NBVersionCheck.MinVersion, "NB version check min version mismatch")

		// Validate OS Version Check
		require.NotNil(t, pc1.Checks.OSVersionCheck, "OS version check should not be nil")
		require.NotNil(t, pc1.Checks.OSVersionCheck.Ios, "iOS version check should not be nil")
		assert.Equal(t, "16.0", pc1.Checks.OSVersionCheck.Ios.MinVersion, "iOS min version mismatch")
		require.NotNil(t, pc1.Checks.OSVersionCheck.Darwin, "Darwin version check should not be nil")
		assert.Equal(t, "22.0.0", pc1.Checks.OSVersionCheck.Darwin.MinVersion, "Darwin min version mismatch")

		// Validate Posture Check 2
		require.NotNil(t, pc2, "Posture check 2 should exist")
		assert.Equal(t, "Posture Check 2", pc2.Name, "Posture check 2 name mismatch")

		// Validate Geo Location Check
		require.NotNil(t, pc2.Checks.GeoLocationCheck, "Geo location check should not be nil")
		assert.Equal(t, "allow", pc2.Checks.GeoLocationCheck.Action, "Geo location action mismatch")
		assert.Len(t, pc2.Checks.GeoLocationCheck.Locations, 2, "Geo location check should have 2 locations")
		assert.Equal(t, "US", pc2.Checks.GeoLocationCheck.Locations[0].CountryCode, "Location 1 country code mismatch")
		assert.Equal(t, "San Francisco", pc2.Checks.GeoLocationCheck.Locations[0].CityName, "Location 1 city name mismatch")
		assert.Equal(t, "GB", pc2.Checks.GeoLocationCheck.Locations[1].CountryCode, "Location 2 country code mismatch")
		assert.Equal(t, "London", pc2.Checks.GeoLocationCheck.Locations[1].CityName, "Location 2 city name mismatch")

		// Validate Peer Network Range Check
		require.NotNil(t, pc2.Checks.PeerNetworkRangeCheck, "Peer network range check should not be nil")
		assert.Equal(t, "allow", pc2.Checks.PeerNetworkRangeCheck.Action, "Peer network range action mismatch")
		assert.Len(t, pc2.Checks.PeerNetworkRangeCheck.Ranges, 2, "Peer network range check should have 2 ranges")
		assert.Contains(t, pc2.Checks.PeerNetworkRangeCheck.Ranges, netip.MustParsePrefix("192.168.0.0/16"), "Should have 192.168.0.0/16 range")
		assert.Contains(t, pc2.Checks.PeerNetworkRangeCheck.Ranges, netip.MustParsePrefix("10.0.0.0/8"), "Should have 10.0.0.0/8 range")
	})

	// ========== VALIDATE NETWORKS ==========
	t.Run("Networks", func(t *testing.T) {
		require.Len(t, retrievedAccount.Networks, 1, "Should have 1 network")

		net1 := retrievedAccount.Networks[0]
		assert.Equal(t, networkID1, net1.ID, "Network 1 ID mismatch")
		assert.Equal(t, "Network 1", net1.Name, "Network 1 name mismatch")
		assert.Equal(t, "Primary network", net1.Description, "Network 1 description mismatch")
	})

	// ========== VALIDATE NETWORK ROUTERS ==========
	t.Run("NetworkRouters", func(t *testing.T) {
		require.Len(t, retrievedAccount.NetworkRouters, 1, "Should have 1 network router")

		router := retrievedAccount.NetworkRouters[0]
		assert.Equal(t, routerID1, router.ID, "Router 1 ID mismatch")
		assert.Equal(t, networkID1, router.NetworkID, "Router 1 network ID mismatch")
		assert.Equal(t, peerID1, router.Peer, "Router 1 peer mismatch")
		assert.Empty(t, router.PeerGroups, "Router 1 peer groups should be empty")
		assert.True(t, router.Masquerade, "Router 1 masquerade should be enabled")
		assert.Equal(t, 100, router.Metric, "Router 1 metric mismatch")
	})

	// ========== VALIDATE NETWORK RESOURCES ==========
	t.Run("NetworkResources", func(t *testing.T) {
		require.Len(t, retrievedAccount.NetworkResources, 1, "Should have 1 network resource")

		res := retrievedAccount.NetworkResources[0]
		assert.Equal(t, resourceID1, res.ID, "Resource 1 ID mismatch")
		assert.Equal(t, networkID1, res.NetworkID, "Resource 1 network ID mismatch")
		assert.Equal(t, "Resource 1", res.Name, "Resource 1 name mismatch")
		assert.Equal(t, "Web server", res.Description, "Resource 1 description mismatch")
		assert.Equal(t, netip.MustParsePrefix("192.168.1.100/32"), res.Prefix, "Resource 1 prefix mismatch")
		assert.Equal(t, resourceTypes.Host, res.Type, "Resource 1 type mismatch")
	})

	// ========== VALIDATE ONBOARDING ==========
	t.Run("Onboarding", func(t *testing.T) {
		assert.Equal(t, accountID, retrievedAccount.Onboarding.AccountID, "Onboarding account ID mismatch")
		assert.True(t, retrievedAccount.Onboarding.OnboardingFlowPending, "Onboarding flow should be pending")
		assert.False(t, retrievedAccount.Onboarding.SignupFormPending, "Signup form should not be pending")
		assert.WithinDuration(t, now, retrievedAccount.Onboarding.CreatedAt, time.Second, "Onboarding created at mismatch")
	})

	t.Log("✅ All comprehensive account field validations passed!")
}
