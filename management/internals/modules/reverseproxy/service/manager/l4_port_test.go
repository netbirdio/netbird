package manager

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const testCluster = "test-cluster"

func boolPtr(v bool) *bool { return &v }

// setupL4Test creates a manager with a mock proxy controller for L4 port tests.
func setupL4Test(t *testing.T, customPortsSupported *bool) (*Manager, store.Store, *proxy.MockController) {
	t.Helper()

	ctrl := gomock.NewController(t)

	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	err = testStore.SaveAccount(ctx, &types.Account{
		Id:        testAccountID,
		CreatedBy: testUserID,
		Settings: &types.Settings{
			PeerExposeEnabled: true,
			PeerExposeGroups:  []string{testGroupID},
		},
		Users: map[string]*types.User{
			testUserID: {
				Id:        testUserID,
				AccountID: testAccountID,
				Role:      types.UserRoleAdmin,
			},
		},
		Peers: map[string]*nbpeer.Peer{
			testPeerID: {
				ID:        testPeerID,
				AccountID: testAccountID,
				Key:       "test-key",
				DNSLabel:  "test-peer",
				Name:      "test-peer",
				IP:        net.ParseIP("100.64.0.1"),
				Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
				Meta:      nbpeer.PeerSystemMeta{Hostname: "test-peer"},
			},
		},
		Groups: map[string]*types.Group{
			testGroupID: {
				ID:        testGroupID,
				AccountID: testAccountID,
				Name:      "Expose Group",
			},
		},
	})
	require.NoError(t, err)

	err = testStore.AddPeerToGroup(ctx, testAccountID, testPeerID, testGroupID)
	require.NoError(t, err)

	mockCtrl := proxy.NewMockController(ctrl)
	mockCtrl.EXPECT().SendServiceUpdateToCluster(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockCtrl.EXPECT().GetOIDCValidationConfig().Return(proxy.OIDCValidationConfig{}).AnyTimes()

	mockCaps := proxy.NewMockManager(ctrl)
	mockCaps.EXPECT().ClusterSupportsCustomPorts(gomock.Any(), testCluster).Return(customPortsSupported).AnyTimes()
	mockCaps.EXPECT().ClusterRequireSubdomain(gomock.Any(), testCluster).Return((*bool)(nil)).AnyTimes()
	mockCaps.EXPECT().ClusterSupportsCrowdSec(gomock.Any(), testCluster).Return((*bool)(nil)).AnyTimes()

	accountMgr := &mock_server.MockAccountManager{
		StoreEventFunc:         func(_ context.Context, _, _, _ string, _ activity.ActivityDescriber, _ map[string]any) {},
		UpdateAccountPeersFunc: func(_ context.Context, _ string, _ types.UpdateReason) {},
		GetGroupByNameFunc: func(ctx context.Context, groupName, accountID, userID string) (*types.Group, error) {
			return testStore.GetGroupByName(ctx, store.LockingStrengthNone, accountID, groupName)
		},
	}

	mgr := &Manager{
		store:              testStore,
		accountManager:     accountMgr,
		permissionsManager: permissions.NewManager(testStore),
		proxyController:    mockCtrl,
		capabilities:       mockCaps,
		clusterDeriver:     &testClusterDeriver{domains: []string{"test.netbird.io"}},
	}
	mgr.exposeReaper = &exposeReaper{manager: mgr}

	return mgr, testStore, mockCtrl
}

// seedService creates a service directly in the store for test setup.
func seedService(t *testing.T, s store.Store, name, protocol, domain, cluster string, port uint16) *rpservice.Service {
	t.Helper()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         name,
		Mode:         protocol,
		Domain:       domain,
		ProxyCluster: cluster,
		ListenPort:   port,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: protocol, Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()
	err := s.CreateService(context.Background(), svc)
	require.NoError(t, err)
	return svc
}

func TestPortConflict_TCPSamePortCluster(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	seedService(t, testStore, "existing-tcp", "tcp", testCluster, testCluster, 5432)

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "conflicting-tcp",
		Mode:         "tcp",
		Domain:       "conflicting-tcp." + testCluster,
		ProxyCluster: testCluster,
		ListenPort:   5432,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 9090, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.Error(t, err, "TCP+TCP on same port/cluster should be rejected")
	assert.Contains(t, err.Error(), "already in use")
}

func TestPortConflict_UDPSamePortCluster(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	seedService(t, testStore, "existing-udp", "udp", testCluster, testCluster, 5432)

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "conflicting-udp",
		Mode:         "udp",
		Domain:       "conflicting-udp." + testCluster,
		ProxyCluster: testCluster,
		ListenPort:   5432,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "udp", Port: 9090, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.Error(t, err, "UDP+UDP on same port/cluster should be rejected")
	assert.Contains(t, err.Error(), "already in use")
}

func TestPortConflict_TLSSamePortDifferentDomain(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	seedService(t, testStore, "existing-tls", "tls", "app1.example.com", testCluster, 443)

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "new-tls",
		Mode:         "tls",
		Domain:       "app2.example.com",
		ProxyCluster: testCluster,
		ListenPort:   443,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8443, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	assert.NoError(t, err, "TLS+TLS on same port with different domains should be allowed (SNI routing)")
}

func TestPortConflict_TLSSamePortSameDomain(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	seedService(t, testStore, "existing-tls", "tls", "app.example.com", testCluster, 443)

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "duplicate-tls",
		Mode:         "tls",
		Domain:       "app.example.com",
		ProxyCluster: testCluster,
		ListenPort:   443,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8443, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.Error(t, err, "TLS+TLS on same domain should be rejected")
	assert.Contains(t, err.Error(), "domain already taken")
}

func TestPortConflict_TLSAndTCPSamePort(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	seedService(t, testStore, "existing-tls", "tls", "app.example.com", testCluster, 443)

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "new-tcp",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   443,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	assert.NoError(t, err, "TLS+TCP on same port should be allowed (multiplexed)")
}

func TestAutoAssign_TCPNoListenPort(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "auto-tcp",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   0,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.NoError(t, err)
	assert.True(t, svc.ListenPort >= autoAssignPortMin && svc.ListenPort <= autoAssignPortMax,
		"auto-assigned port %d should be in range [%d, %d]", svc.ListenPort, autoAssignPortMin, autoAssignPortMax)
	assert.True(t, svc.PortAutoAssigned, "PortAutoAssigned should be set")
}

func TestAutoAssign_TCPCustomPortRejectedWhenNotSupported(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "custom-tcp",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   5555,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.Error(t, err, "TCP with custom port should be rejected when cluster doesn't support it")
	assert.Contains(t, err.Error(), "custom ports")
}

func TestAutoAssign_TLSCustomPortAlwaysAllowed(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "custom-tls",
		Mode:         "tls",
		Domain:       "app.example.com",
		ProxyCluster: testCluster,
		ListenPort:   9999,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8443, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	assert.NoError(t, err, "TLS with custom port should always be allowed regardless of cluster capability")
	assert.Equal(t, uint16(9999), svc.ListenPort, "TLS listen port should not be overridden")
	assert.False(t, svc.PortAutoAssigned, "PortAutoAssigned should not be set for TLS")
}

func TestAutoAssign_EphemeralOverridesPortWhenNotSupported(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "ephemeral-tcp",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   5555,
		Enabled:      true,
		Source:       "ephemeral",
		SourcePeer:   testPeerID,
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewEphemeralService(ctx, testAccountID, testPeerID, svc)
	require.NoError(t, err)
	assert.NotEqual(t, uint16(5555), svc.ListenPort, "requested port should be overridden")
	assert.True(t, svc.ListenPort >= autoAssignPortMin && svc.ListenPort <= autoAssignPortMax,
		"auto-assigned port %d should be in range", svc.ListenPort)
	assert.True(t, svc.PortAutoAssigned)
}

func TestAutoAssign_EphemeralTLSKeepsCustomPort(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "ephemeral-tls",
		Mode:         "tls",
		Domain:       "app.example.com",
		ProxyCluster: testCluster,
		ListenPort:   9999,
		Enabled:      true,
		Source:       "ephemeral",
		SourcePeer:   testPeerID,
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8443, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewEphemeralService(ctx, testAccountID, testPeerID, svc)
	require.NoError(t, err)
	assert.Equal(t, uint16(9999), svc.ListenPort, "TLS listen port should not be overridden")
	assert.False(t, svc.PortAutoAssigned)
}

func TestAutoAssign_AvoidsExistingPorts(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	existingPort := uint16(20000)
	seedService(t, testStore, "existing", "tcp", testCluster, testCluster, existingPort)

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "auto-tcp",
		Mode:         "tcp",
		Domain:       "auto-tcp." + testCluster,
		ProxyCluster: testCluster,
		ListenPort:   0,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.NoError(t, err)
	assert.NotEqual(t, existingPort, svc.ListenPort, "auto-assigned port should not collide with existing")
	assert.True(t, svc.PortAutoAssigned)
}

func TestAutoAssign_TCPCustomPortAllowedWhenSupported(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	svc := &rpservice.Service{
		AccountID:    testAccountID,
		Name:         "custom-tcp",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   5555,
		Enabled:      true,
		Source:       "permanent",
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 8080, Enabled: true},
		},
	}
	svc.InitNewRecord()

	err := mgr.persistNewService(ctx, testAccountID, svc)
	require.NoError(t, err)
	assert.Equal(t, uint16(5555), svc.ListenPort, "custom port should be preserved when supported")
	assert.False(t, svc.PortAutoAssigned)
}

func TestUpdate_PreservesExistingListenPort(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	existing := seedService(t, testStore, "tcp-svc", "tcp", testCluster, testCluster, 12345)

	updated := &rpservice.Service{
		ID:           existing.ID,
		AccountID:    testAccountID,
		Name:         "tcp-svc-renamed",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   0,
		Enabled:      true,
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 9090, Enabled: true},
		},
	}

	_, err := mgr.persistServiceUpdate(ctx, testAccountID, updated)
	require.NoError(t, err)
	assert.Equal(t, uint16(12345), updated.ListenPort, "existing listen port should be preserved when update sends 0")
}

func TestUpdate_AllowsPortChange(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	existing := seedService(t, testStore, "tcp-svc", "tcp", testCluster, testCluster, 12345)

	updated := &rpservice.Service{
		ID:           existing.ID,
		AccountID:    testAccountID,
		Name:         "tcp-svc",
		Mode:         "tcp",
		Domain:       testCluster,
		ProxyCluster: testCluster,
		ListenPort:   54321,
		Enabled:      true,
		Targets: []*rpservice.Target{
			{AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer, Protocol: "tcp", Port: 9090, Enabled: true},
		},
	}

	_, err := mgr.persistServiceUpdate(ctx, testAccountID, updated)
	require.NoError(t, err)
	assert.Equal(t, uint16(54321), updated.ListenPort, "explicit port change should be applied")
}

func TestCreateServiceFromPeer_TCP(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 5432,
		Mode: "tcp",
	})
	require.NoError(t, err)

	assert.NotEmpty(t, resp.ServiceName)
	assert.Contains(t, resp.Domain, ".test.netbird.io", "TCP uses unique subdomain")
	assert.True(t, resp.PortAutoAssigned, "port should be auto-assigned when cluster doesn't support custom ports")
	assert.Contains(t, resp.ServiceURL, "tcp://")
}

func TestCreateServiceFromPeer_TCP_CustomPort(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port:       5432,
		Mode:       "tcp",
		ListenPort: 15432,
	})
	require.NoError(t, err)

	assert.False(t, resp.PortAutoAssigned)
	assert.Contains(t, resp.ServiceURL, ":15432")
}

func TestCreateServiceFromPeer_TCP_DefaultListenPort(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 5432,
		Mode: "tcp",
	})
	require.NoError(t, err)

	// When no explicit listen port, defaults to target port
	assert.Contains(t, resp.ServiceURL, ":5432")
	assert.False(t, resp.PortAutoAssigned)
}

func TestCreateServiceFromPeer_TLS(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(false))
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 443,
		Mode: "tls",
	})
	require.NoError(t, err)

	assert.Contains(t, resp.Domain, ".test.netbird.io", "TLS uses subdomain")
	assert.Contains(t, resp.ServiceURL, "tls://")
	assert.Contains(t, resp.ServiceURL, ":443")
	// TLS always keeps its port (not port-based protocol for auto-assign)
	assert.False(t, resp.PortAutoAssigned)
}

func TestCreateServiceFromPeer_TCP_StopAndRenew(t *testing.T) {
	mgr, testStore, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8080,
		Mode: "tcp",
	})
	require.NoError(t, err)

	svcID := resolveServiceIDByDomain(t, testStore, resp.Domain)

	err = mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, svcID)
	require.NoError(t, err)

	err = mgr.StopServiceFromPeer(ctx, testAccountID, testPeerID, svcID)
	require.NoError(t, err)

	// Renew after stop should fail
	err = mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, svcID)
	require.Error(t, err)
}

func TestCreateServiceFromPeer_L4_RejectsAuth(t *testing.T) {
	mgr, _, _ := setupL4Test(t, boolPtr(true))
	ctx := context.Background()

	_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8080,
		Mode: "tcp",
		Pin:  "123456",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication is not supported")
}
