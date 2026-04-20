package manager

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	cachestore "github.com/eko/gocache/lib/v4/store"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/mock_server"
	resourcetypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func testCacheStore(t *testing.T) cachestore.StoreInterface {
	t.Helper()
	s, err := nbcache.NewStore(context.Background(), 30*time.Minute, 10*time.Minute, 100)
	require.NoError(t, err)
	return s
}

func TestInitializeServiceForCreate(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	t.Run("successful initialization without cluster deriver", func(t *testing.T) {
		mgr := &Manager{
			clusterDeriver: nil,
		}

		service := &rpservice.Service{
			Domain: "example.com",
			Auth:   rpservice.AuthConfig{},
		}

		err := mgr.initializeServiceForCreate(ctx, accountID, service)

		assert.NoError(t, err)
		assert.Equal(t, accountID, service.AccountID)
		assert.Empty(t, service.ProxyCluster, "proxy cluster should be empty when no deriver")
		assert.NotEmpty(t, service.ID, "service ID should be initialized")
		assert.NotEmpty(t, service.SessionPrivateKey, "session private key should be generated")
		assert.NotEmpty(t, service.SessionPublicKey, "session public key should be generated")
	})

	t.Run("verifies session keys are different", func(t *testing.T) {
		mgr := &Manager{
			clusterDeriver: nil,
		}

		service1 := &rpservice.Service{Domain: "test1.com", Auth: rpservice.AuthConfig{}}
		service2 := &rpservice.Service{Domain: "test2.com", Auth: rpservice.AuthConfig{}}

		err1 := mgr.initializeServiceForCreate(ctx, accountID, service1)
		err2 := mgr.initializeServiceForCreate(ctx, accountID, service2)

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, service1.SessionPrivateKey, service2.SessionPrivateKey, "private keys should be unique")
		assert.NotEqual(t, service1.SessionPublicKey, service2.SessionPublicKey, "public keys should be unique")
	})
}

func TestCheckDomainAvailable(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		domain           string
		excludeServiceID string
		setupMock        func(*store.MockStore)
		expectedError    bool
		errorType        status.Type
	}{
		{
			name:             "domain available - not found",
			domain:           "available.com",
			excludeServiceID: "",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, "available.com").
					Return(nil, status.Errorf(status.NotFound, "not found"))
			},
			expectedError: false,
		},
		{
			name:             "domain already exists",
			domain:           "exists.com",
			excludeServiceID: "",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, "exists.com").
					Return(&rpservice.Service{ID: "existing-id", Domain: "exists.com"}, nil)
			},
			expectedError: true,
			errorType:     status.AlreadyExists,
		},
		{
			name:             "domain exists but excluded (same ID)",
			domain:           "exists.com",
			excludeServiceID: "service-123",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, "exists.com").
					Return(&rpservice.Service{ID: "service-123", Domain: "exists.com"}, nil)
			},
			expectedError: false,
		},
		{
			name:             "domain exists with different ID",
			domain:           "exists.com",
			excludeServiceID: "service-456",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, "exists.com").
					Return(&rpservice.Service{ID: "service-123", Domain: "exists.com"}, nil)
			},
			expectedError: true,
			errorType:     status.AlreadyExists,
		},
		{
			name:             "store error (non-NotFound)",
			domain:           "error.com",
			excludeServiceID: "",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, "error.com").
					Return(nil, errors.New("database error"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := store.NewMockStore(ctrl)
			tt.setupMock(mockStore)

			mgr := &Manager{}
			err := mgr.checkDomainAvailable(ctx, mockStore, tt.domain, tt.excludeServiceID)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorType != 0 {
					sErr, ok := status.FromError(err)
					require.True(t, ok, "error should be a status error")
					assert.Equal(t, tt.errorType, sErr.Type())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckDomainAvailable_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("empty domain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, "").
			Return(nil, status.Errorf(status.NotFound, "not found"))

		mgr := &Manager{}
		err := mgr.checkDomainAvailable(ctx, mockStore, "", "")

		assert.NoError(t, err)
	})

	t.Run("empty exclude ID with existing service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, "test.com").
			Return(&rpservice.Service{ID: "some-id", Domain: "test.com"}, nil)

		mgr := &Manager{}
		err := mgr.checkDomainAvailable(ctx, mockStore, "test.com", "")

		assert.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())
	})

	t.Run("nil existing service with nil error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, "nil.com").
			Return(nil, nil)

		mgr := &Manager{}
		err := mgr.checkDomainAvailable(ctx, mockStore, "nil.com", "")

		assert.NoError(t, err)
	})
}

func TestPersistNewService(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	t.Run("successful service creation with no targets", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		service := &rpservice.Service{
			ID:      "service-123",
			Domain:  "new.com",
			Targets: []*rpservice.Target{},
		}

		// Mock ExecuteInTransaction to execute the function immediately
		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				// Create another mock for the transaction
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByDomain(ctx, "new.com").
					Return(nil, status.Errorf(status.NotFound, "not found"))
				txMock.EXPECT().
					CreateService(ctx, service).
					Return(nil)

				return fn(txMock)
			})

		mgr := &Manager{store: mockStore}
		err := mgr.persistNewService(ctx, accountID, service)

		assert.NoError(t, err)
	})

	t.Run("domain already exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		service := &rpservice.Service{
			ID:      "service-123",
			Domain:  "existing.com",
			Targets: []*rpservice.Target{},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByDomain(ctx, "existing.com").
					Return(&rpservice.Service{ID: "other-id", Domain: "existing.com"}, nil)

				return fn(txMock)
			})

		mgr := &Manager{store: mockStore}
		err := mgr.persistNewService(ctx, accountID, service)

		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())
	})
}
func TestPreserveExistingAuthSecrets(t *testing.T) {
	mgr := &Manager{}

	t.Run("preserve password when empty", func(t *testing.T) {
		existing := &rpservice.Service{
			Auth: rpservice.AuthConfig{
				PasswordAuth: &rpservice.PasswordAuthConfig{
					Enabled:  true,
					Password: "hashed-password",
				},
			},
		}

		updated := &rpservice.Service{
			Auth: rpservice.AuthConfig{
				PasswordAuth: &rpservice.PasswordAuthConfig{
					Enabled:  true,
					Password: "",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, existing.Auth.PasswordAuth, updated.Auth.PasswordAuth)
	})

	t.Run("preserve pin when empty", func(t *testing.T) {
		existing := &rpservice.Service{
			Auth: rpservice.AuthConfig{
				PinAuth: &rpservice.PINAuthConfig{
					Enabled: true,
					Pin:     "hashed-pin",
				},
			},
		}

		updated := &rpservice.Service{
			Auth: rpservice.AuthConfig{
				PinAuth: &rpservice.PINAuthConfig{
					Enabled: true,
					Pin:     "",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, existing.Auth.PinAuth, updated.Auth.PinAuth)
	})

	t.Run("do not preserve when password is provided", func(t *testing.T) {
		existing := &rpservice.Service{
			Auth: rpservice.AuthConfig{
				PasswordAuth: &rpservice.PasswordAuthConfig{
					Enabled:  true,
					Password: "old-password",
				},
			},
		}

		updated := &rpservice.Service{
			Auth: rpservice.AuthConfig{
				PasswordAuth: &rpservice.PasswordAuthConfig{
					Enabled:  true,
					Password: "new-password",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, "new-password", updated.Auth.PasswordAuth.Password)
		assert.NotEqual(t, existing.Auth.PasswordAuth, updated.Auth.PasswordAuth)
	})
}

func TestPreserveServiceMetadata(t *testing.T) {
	mgr := &Manager{}

	existing := &rpservice.Service{
		Meta: rpservice.Meta{
			CertificateIssuedAt: func() *time.Time { t := time.Now(); return &t }(),
			Status:              "active",
		},
		SessionPrivateKey: "private-key",
		SessionPublicKey:  "public-key",
	}

	updated := &rpservice.Service{
		Domain: "updated.com",
	}

	mgr.preserveServiceMetadata(updated, existing)

	assert.Equal(t, existing.Meta, updated.Meta)
	assert.Equal(t, existing.SessionPrivateKey, updated.SessionPrivateKey)
	assert.Equal(t, existing.SessionPublicKey, updated.SessionPublicKey)
}

func TestDeletePeerService_SourcePeerValidation(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"
	ownerPeerID := "peer-owner"
	otherPeerID := "peer-other"
	serviceID := "service-123"

	testPeer := &nbpeer.Peer{
		ID:   ownerPeerID,
		Name: "test-peer",
		IP:   net.ParseIP("100.64.0.1"),
	}

	newEphemeralService := func() *rpservice.Service {
		return &rpservice.Service{
			ID:         serviceID,
			AccountID:  accountID,
			Name:       "test-service",
			Domain:     "test.example.com",
			Source:     rpservice.SourceEphemeral,
			SourcePeer: ownerPeerID,
		}
	}

	newPermanentService := func() *rpservice.Service {
		return &rpservice.Service{
			ID:        serviceID,
			AccountID: accountID,
			Name:      "api-service",
			Domain:    "api.example.com",
			Source:    rpservice.SourcePermanent,
		}
	}

	newProxyServer := func(t *testing.T) *nbgrpc.ProxyServiceServer {
		t.Helper()
		tokenStore := nbgrpc.NewOneTimeTokenStore(context.Background(), testCacheStore(t))
		pkceStore := nbgrpc.NewPKCEVerifierStore(context.Background(), testCacheStore(t))
		srv := nbgrpc.NewProxyServiceServer(nil, tokenStore, pkceStore, nbgrpc.ProxyOIDCConfig{}, nil, nil, nil)
		return srv
	}

	t.Run("owner peer can delete own service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var storedActivity activity.Activity
		mockStore := store.NewMockStore(ctrl)
		mockAccountMgr := &mock_server.MockAccountManager{
			StoreEventFunc: func(_ context.Context, _, _, _ string, activityID activity.ActivityDescriber, _ map[string]any) {
				storedActivity = activityID.(activity.Activity)
			},
			UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				txMock.EXPECT().
					DeleteService(ctx, accountID, serviceID).
					Return(nil)
				return fn(txMock)
			})
		mockStore.EXPECT().
			GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
			Return(testPeer, nil)

		mgr := &Manager{
			store:          mockStore,
			accountManager: mockAccountMgr,
			proxyController: func() proxy.Controller {
				c, err := proxymanager.NewGRPCController(newProxyServer(t), noop.NewMeterProvider().Meter(""))
				require.NoError(t, err)
				return c
			}(),
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceUnexposed)
		require.NoError(t, err)
		assert.Equal(t, activity.PeerServiceUnexposed, storedActivity, "should store unexposed activity")
	})

	t.Run("different peer cannot delete service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				return fn(txMock)
			})

		mgr := &Manager{
			store: mockStore,
		}

		err := mgr.deletePeerService(ctx, accountID, otherPeerID, serviceID, activity.PeerServiceUnexposed)
		require.Error(t, err)

		sErr, ok := status.FromError(err)
		require.True(t, ok, "should be a status error")
		assert.Equal(t, status.PermissionDenied, sErr.Type(), "should be permission denied")
		assert.Contains(t, err.Error(), "another peer")
	})

	t.Run("cannot delete API-created service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newPermanentService(), nil)
				return fn(txMock)
			})

		mgr := &Manager{
			store: mockStore,
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceUnexposed)
		require.Error(t, err)

		sErr, ok := status.FromError(err)
		require.True(t, ok, "should be a status error")
		assert.Equal(t, status.PermissionDenied, sErr.Type(), "should be permission denied")
		assert.Contains(t, err.Error(), "API-created")
	})

	t.Run("expire uses correct activity code", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var storedActivity activity.Activity
		mockStore := store.NewMockStore(ctrl)
		mockAccountMgr := &mock_server.MockAccountManager{
			StoreEventFunc: func(_ context.Context, _, _, _ string, activityID activity.ActivityDescriber, _ map[string]any) {
				storedActivity = activityID.(activity.Activity)
			},
			UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				txMock.EXPECT().
					DeleteService(ctx, accountID, serviceID).
					Return(nil)
				return fn(txMock)
			})
		mockStore.EXPECT().
			GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
			Return(testPeer, nil)

		mgr := &Manager{
			store:          mockStore,
			accountManager: mockAccountMgr,
			proxyController: func() proxy.Controller {
				c, err := proxymanager.NewGRPCController(newProxyServer(t), noop.NewMeterProvider().Meter(""))
				require.NoError(t, err)
				return c
			}(),
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceExposeExpired)
		require.NoError(t, err)
		assert.Equal(t, activity.PeerServiceExposeExpired, storedActivity, "should store expired activity")
	})

	t.Run("event meta includes peer info", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var storedMeta map[string]any
		mockStore := store.NewMockStore(ctrl)
		mockAccountMgr := &mock_server.MockAccountManager{
			StoreEventFunc: func(_ context.Context, _, _, _ string, _ activity.ActivityDescriber, meta map[string]any) {
				storedMeta = meta
			},
			UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				txMock.EXPECT().
					DeleteService(ctx, accountID, serviceID).
					Return(nil)
				return fn(txMock)
			})
		mockStore.EXPECT().
			GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
			Return(testPeer, nil)

		mgr := &Manager{
			store:          mockStore,
			accountManager: mockAccountMgr,
			proxyController: func() proxy.Controller {
				c, err := proxymanager.NewGRPCController(newProxyServer(t), noop.NewMeterProvider().Meter(""))
				require.NoError(t, err)
				return c
			}(),
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceUnexposed)
		require.NoError(t, err)
		require.NotNil(t, storedMeta)
		assert.Equal(t, "test-peer", storedMeta["peer_name"], "meta should contain peer name")
		assert.Equal(t, "100.64.0.1", storedMeta["peer_ip"], "meta should contain peer IP")
		assert.Equal(t, "test-service", storedMeta["name"], "meta should contain service name")
		assert.Equal(t, "test.example.com", storedMeta["domain"], "meta should contain service domain")
	})
}

// testClusterDeriver is a minimal ClusterDeriver that returns a fixed domain list.
type testClusterDeriver struct {
	domains []string
}

func (d *testClusterDeriver) DeriveClusterFromDomain(_ context.Context, _, domain string) (string, error) {
	return "test-cluster", nil
}

func (d *testClusterDeriver) GetClusterDomains() []string {
	return d.domains
}

const (
	testAccountID = "test-account"
	testPeerID    = "test-peer-1"
	testGroupID   = "test-group-1"
	testUserID    = "test-user"
)

// setupIntegrationTest creates a real SQLite store with seeded test data for integration tests.
func setupIntegrationTest(t *testing.T) (*Manager, store.Store) {
	t.Helper()

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

	permsMgr := permissions.NewManager(testStore)

	accountMgr := &mock_server.MockAccountManager{
		StoreEventFunc:         func(_ context.Context, _, _, _ string, _ activity.ActivityDescriber, _ map[string]any) {},
		UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		GetGroupByNameFunc: func(ctx context.Context, groupName, accountID, userID string) (*types.Group, error) {
			return testStore.GetGroupByName(ctx, store.LockingStrengthNone, accountID, groupName)
		},
	}

	tokenStore := nbgrpc.NewOneTimeTokenStore(ctx, testCacheStore(t))
	pkceStore := nbgrpc.NewPKCEVerifierStore(ctx, testCacheStore(t))
	proxySrv := nbgrpc.NewProxyServiceServer(nil, tokenStore, pkceStore, nbgrpc.ProxyOIDCConfig{}, nil, nil, nil)

	proxyController, err := proxymanager.NewGRPCController(proxySrv, noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)

	mgr := &Manager{
		store:              testStore,
		accountManager:     accountMgr,
		permissionsManager: permsMgr,
		proxyController:    proxyController,
		clusterDeriver: &testClusterDeriver{
			domains: []string{"test.netbird.io"},
		},
	}
	mgr.exposeReaper = &exposeReaper{manager: mgr}

	return mgr, testStore
}

func Test_validateExposePermission(t *testing.T) {
	ctx := context.Background()

	t.Run("allowed when peer is in expose group", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		err := mgr.validateExposePermission(ctx, testAccountID, testPeerID)
		assert.NoError(t, err)
	})

	t.Run("denied when peer is not in expose group", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// Add a peer that is NOT in the expose group
		otherPeerID := "other-peer"
		err := testStore.AddPeerToAccount(ctx, &nbpeer.Peer{
			ID:        otherPeerID,
			AccountID: testAccountID,
			Key:       "other-key",
			DNSLabel:  "other-peer",
			Name:      "other-peer",
			IP:        net.ParseIP("100.64.0.2"),
			Status:    &nbpeer.PeerStatus{LastSeen: time.Now()},
			Meta:      nbpeer.PeerSystemMeta{Hostname: "other-peer"},
		})
		require.NoError(t, err)

		err = mgr.validateExposePermission(ctx, testAccountID, otherPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in an allowed expose group")
	})

	t.Run("denied when expose is disabled", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// Disable peer expose
		s, err := testStore.GetAccountSettings(ctx, store.LockingStrengthNone, testAccountID)
		require.NoError(t, err)
		s.PeerExposeEnabled = false
		err = testStore.SaveAccountSettings(ctx, testAccountID, s)
		require.NoError(t, err)

		err = mgr.validateExposePermission(ctx, testAccountID, testPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("disallowed when no groups configured", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// Enable expose with empty groups — no groups configured means no peer is allowed
		s, err := testStore.GetAccountSettings(ctx, store.LockingStrengthNone, testAccountID)
		require.NoError(t, err)
		s.PeerExposeGroups = []string{}
		err = testStore.SaveAccountSettings(ctx, testAccountID, s)
		require.NoError(t, err)

		err = mgr.validateExposePermission(ctx, testAccountID, testPeerID)
		assert.Error(t, err)
	})

	t.Run("error when store returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().GetAccountSettings(gomock.Any(), gomock.Any(), testAccountID).Return(nil, errors.New("store error"))
		mgr := &Manager{store: mockStore}
		err := mgr.validateExposePermission(ctx, testAccountID, testPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get account settings")
	})
}

func TestCreateServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("creates service with random domain", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		req := &rpservice.ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		}

		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ServiceName, "service name should be generated")
		assert.Contains(t, resp.Domain, "test.netbird.io", "domain should use cluster domain")
		assert.NotEmpty(t, resp.ServiceURL, "service URL should be set")

		// Verify service is persisted in store
		persisted, err := testStore.GetServiceByDomain(ctx, resp.Domain)
		require.NoError(t, err)
		assert.Equal(t, resp.Domain, persisted.Domain)
		assert.Equal(t, rpservice.SourceEphemeral, persisted.Source, "source should be ephemeral")
		assert.Equal(t, testPeerID, persisted.SourcePeer, "source peer should be set")
		assert.NotNil(t, persisted.Meta.LastRenewedAt, "last renewed should be set")
	})

	t.Run("creates service with custom domain", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		req := &rpservice.ExposeServiceRequest{
			Port:   80,
			Mode:   "http",
			Domain: "example.com",
		}

		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)
		assert.Contains(t, resp.Domain, "example.com", "should use the provided domain")
	})

	t.Run("validates expose permission internally", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// Disable peer expose
		s, err := testStore.GetAccountSettings(ctx, store.LockingStrengthNone, testAccountID)
		require.NoError(t, err)
		s.PeerExposeEnabled = false
		err = testStore.SaveAccountSettings(ctx, testAccountID, s)
		require.NoError(t, err)

		req := &rpservice.ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		}

		_, err = mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("validates request fields", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		req := &rpservice.ExposeServiceRequest{
			Port: 0,
			Mode: "http",
		}

		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port")
	})
}

func TestExposeServiceRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		req     rpservice.ExposeServiceRequest
		wantErr string
	}{
		{
			name:    "valid http request",
			req:     rpservice.ExposeServiceRequest{Port: 8080, Mode: "http"},
			wantErr: "",
		},
		{
			name:    "https mode rejected",
			req:     rpservice.ExposeServiceRequest{Port: 443, Mode: "https", Pin: "123456"},
			wantErr: "unsupported mode",
		},
		{
			name:    "port zero rejected",
			req:     rpservice.ExposeServiceRequest{Port: 0, Mode: "http"},
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "unsupported mode",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "ftp"},
			wantErr: "unsupported mode",
		},
		{
			name:    "invalid pin format",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "http", Pin: "abc"},
			wantErr: "invalid pin",
		},
		{
			name:    "pin too short",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "http", Pin: "12345"},
			wantErr: "invalid pin",
		},
		{
			name:    "valid 6-digit pin",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "http", Pin: "000000"},
			wantErr: "",
		},
		{
			name:    "empty user group name",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "http", UserGroups: []string{"valid", ""}},
			wantErr: "user group name cannot be empty",
		},
		{
			name:    "invalid name prefix",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "http", NamePrefix: "INVALID"},
			wantErr: "invalid name prefix",
		},
		{
			name:    "valid name prefix",
			req:     rpservice.ExposeServiceRequest{Port: 80, Mode: "http", NamePrefix: "my-service"},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}

	t.Run("nil receiver", func(t *testing.T) {
		var req *rpservice.ExposeServiceRequest
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request cannot be nil")
	})
}

func TestDeleteServiceFromPeer_ByDomain(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes service by domain", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// First create a service
		req := &rpservice.ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		}
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)

		svcID := resolveServiceIDByDomain(t, testStore, resp.Domain)
		err = mgr.deleteServiceFromPeer(ctx, testAccountID, testPeerID, svcID, false)
		require.NoError(t, err)

		// Verify service is deleted
		_, err = testStore.GetServiceByDomain(ctx, resp.Domain)
		require.Error(t, err, "service should be deleted")
	})

	t.Run("expire uses correct activity", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		req := &rpservice.ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		}
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)

		svcID := resolveServiceIDByDomain(t, testStore, resp.Domain)
		err = mgr.deleteServiceFromPeer(ctx, testAccountID, testPeerID, svcID, true)
		require.NoError(t, err)
	})
}

func TestStopServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("stops service by domain", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		req := &rpservice.ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		}
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)

		svcID := resolveServiceIDByDomain(t, testStore, resp.Domain)
		err = mgr.StopServiceFromPeer(ctx, testAccountID, testPeerID, svcID)
		require.NoError(t, err)

		_, err = testStore.GetServiceByDomain(ctx, resp.Domain)
		require.Error(t, err, "service should be deleted")
	})
}

func TestDeleteService_DeletesEphemeralExpose(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8080,
		Mode: "http",
	})
	require.NoError(t, err)

	count, err := mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "one ephemeral service should exist after create")

	svc, err := testStore.GetServiceByDomain(ctx, resp.Domain)
	require.NoError(t, err)

	err = mgr.DeleteService(ctx, testAccountID, testUserID, svc.ID)
	require.NoError(t, err)

	count, err = mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "ephemeral service should be deleted after API delete")

	_, err = mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 9090,
		Mode: "http",
	})
	assert.NoError(t, err, "new expose should succeed after API delete")
}

func TestDeleteAllServices_DeletesEphemeralExposes(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupIntegrationTest(t)

	for i := range 3 {
		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
			Port: uint16(8080 + i),
			Mode: "http",
		})
		require.NoError(t, err)
	}

	count, err := mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count, "all ephemeral services should exist")

	err = mgr.DeleteAllServices(ctx, testAccountID, testUserID)
	require.NoError(t, err)

	count, err = mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "all ephemeral services should be deleted after DeleteAllServices")
}

func TestRenewServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("renews tracked expose", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
			Port: 8080,
			Mode: "http",
		})
		require.NoError(t, err)

		svcID := resolveServiceIDByDomain(t, testStore, resp.Domain)
		err = mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, svcID)
		require.NoError(t, err)
	})

	t.Run("fails for untracked domain", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		err := mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, "nonexistent-service-id")
		require.Error(t, err)
	})
}

func TestGetGroupIDsFromNames(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves group names to IDs", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		ids, err := mgr.getGroupIDsFromNames(ctx, testAccountID, []string{"Expose Group"})
		require.NoError(t, err)
		require.Len(t, ids, 1, "should return exactly one group ID")
		assert.Equal(t, testGroupID, ids[0])
	})

	t.Run("returns error for unknown group", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		_, err := mgr.getGroupIDsFromNames(ctx, testAccountID, []string{"nonexistent"})
		require.Error(t, err)
	})

	t.Run("returns error for empty group list", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		_, err := mgr.getGroupIDsFromNames(ctx, testAccountID, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no group names provided")
	})
}

func TestDeleteService_DeletesTargets(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"
	userID := "test-user"

	sqlStore, err := store.NewStore(ctx, types.SqliteStoreEngine, t.TempDir(), nil, false)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPerms := permissions.NewMockManager(ctrl)
	mockAcct := account.NewMockManager(ctrl)

	tokenStore := nbgrpc.NewOneTimeTokenStore(ctx, testCacheStore(t))
	pkceStore := nbgrpc.NewPKCEVerifierStore(ctx, testCacheStore(t))
	proxySrv := nbgrpc.NewProxyServiceServer(nil, tokenStore, pkceStore, nbgrpc.ProxyOIDCConfig{}, nil, nil, nil)

	proxyController, err := proxymanager.NewGRPCController(proxySrv, noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)

	mgr := &Manager{
		store:              sqlStore,
		permissionsManager: mockPerms,
		accountManager:     mockAcct,
		proxyController:    proxyController,
	}

	service := &rpservice.Service{
		ID:           "service-1",
		AccountID:    accountID,
		Domain:       "test.example.com",
		ProxyCluster: "cluster1",
		Enabled:      true,
		Targets: []*rpservice.Target{
			{AccountID: accountID, ServiceID: "service-1", TargetType: rpservice.TargetTypePeer, TargetId: "peer-1"},
			{AccountID: accountID, ServiceID: "service-1", TargetType: rpservice.TargetTypePeer, TargetId: "peer-2"},
			{AccountID: accountID, ServiceID: "service-1", TargetType: rpservice.TargetTypePeer, TargetId: "peer-3"},
		},
	}

	err = sqlStore.CreateService(ctx, service)
	require.NoError(t, err)

	retrievedService, err := sqlStore.GetServiceByID(ctx, store.LockingStrengthNone, accountID, service.ID)
	require.NoError(t, err)
	require.Len(t, retrievedService.Targets, 3, "Service should have 3 targets before deletion")

	mockPerms.EXPECT().
		ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Delete).
		Return(true, nil)
	mockAcct.EXPECT().
		StoreEvent(ctx, userID, service.ID, accountID, activity.ServiceDeleted, gomock.Any())
	mockAcct.EXPECT().
		UpdateAccountPeers(ctx, accountID)

	err = mgr.DeleteService(ctx, accountID, userID, service.ID)
	require.NoError(t, err)

	_, err = sqlStore.GetServiceByID(ctx, store.LockingStrengthNone, accountID, service.ID)
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, s.Type())

	targets, err := sqlStore.GetTargetsByServiceID(ctx, store.LockingStrengthNone, accountID, service.ID)
	require.NoError(t, err)
	assert.Len(t, targets, 0, "All targets should be deleted when service is deleted")
}

func TestValidateProtocolChange(t *testing.T) {
	tests := []struct {
		name    string
		oldP    string
		newP    string
		wantErr bool
	}{
		{"empty to http", "", "http", false},
		{"http to http", "http", "http", false},
		{"same protocol", "tcp", "tcp", false},
		{"empty new proto", "tcp", "", false},
		{"http to tcp", "http", "tcp", true},
		{"tcp to udp", "tcp", "udp", true},
		{"tls to http", "tls", "http", true},
		{"udp to tls", "udp", "tls", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProtocolChange(tt.oldP, tt.newP)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "cannot change mode")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTargetReferences_ResourceTypeMismatch(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	accountID := "test-account"

	tests := []struct {
		name         string
		targetType   rpservice.TargetType
		resourceType resourcetypes.NetworkResourceType
		wantErr      bool
	}{
		{"host matches host", rpservice.TargetTypeHost, resourcetypes.Host, false},
		{"domain matches domain", rpservice.TargetTypeDomain, resourcetypes.Domain, false},
		{"subnet matches subnet", rpservice.TargetTypeSubnet, resourcetypes.Subnet, false},
		{"host but resource is domain", rpservice.TargetTypeHost, resourcetypes.Domain, true},
		{"domain but resource is host", rpservice.TargetTypeDomain, resourcetypes.Host, true},
		{"host but resource is subnet", rpservice.TargetTypeHost, resourcetypes.Subnet, true},
		{"subnet but resource is domain", rpservice.TargetTypeSubnet, resourcetypes.Domain, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.EXPECT().
				GetNetworkResourceByID(gomock.Any(), store.LockingStrengthShare, accountID, "resource-1").
				Return(&resourcetypes.NetworkResource{Type: tt.resourceType}, nil)

			targets := []*rpservice.Target{
				{TargetId: "resource-1", TargetType: tt.targetType, Host: "10.0.0.1"},
			}
			err := validateTargetReferences(ctx, mockStore, accountID, targets)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "target_type")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTargetReferences_PeerValid(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	accountID := "test-account"

	mockStore.EXPECT().
		GetPeerByID(gomock.Any(), store.LockingStrengthShare, accountID, "peer-1").
		Return(&nbpeer.Peer{}, nil)

	targets := []*rpservice.Target{
		{TargetId: "peer-1", TargetType: rpservice.TargetTypePeer},
	}
	require.NoError(t, validateTargetReferences(ctx, mockStore, accountID, targets))
}

func TestValidateSubdomainRequirement(t *testing.T) {
	ptrBool := func(b bool) *bool { return &b }

	tests := []struct {
		name             string
		domain           string
		cluster          string
		requireSubdomain *bool
		wantErr          bool
	}{
		{
			name:             "subdomain present, require_subdomain true",
			domain:           "app.eu1.proxy.netbird.io",
			cluster:          "eu1.proxy.netbird.io",
			requireSubdomain: ptrBool(true),
			wantErr:          false,
		},
		{
			name:             "bare cluster domain, require_subdomain true",
			domain:           "eu1.proxy.netbird.io",
			cluster:          "eu1.proxy.netbird.io",
			requireSubdomain: ptrBool(true),
			wantErr:          true,
		},
		{
			name:             "bare cluster domain, require_subdomain false",
			domain:           "eu1.proxy.netbird.io",
			cluster:          "eu1.proxy.netbird.io",
			requireSubdomain: ptrBool(false),
			wantErr:          false,
		},
		{
			name:             "bare cluster domain, require_subdomain nil (default)",
			domain:           "eu1.proxy.netbird.io",
			cluster:          "eu1.proxy.netbird.io",
			requireSubdomain: nil,
			wantErr:          false,
		},
		{
			name:             "custom domain apex is not the cluster",
			domain:           "example.com",
			cluster:          "eu1.proxy.netbird.io",
			requireSubdomain: ptrBool(true),
			wantErr:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockCaps := proxy.NewMockManager(ctrl)
			mockCaps.EXPECT().ClusterRequireSubdomain(gomock.Any(), tc.cluster).Return(tc.requireSubdomain).AnyTimes()

			mgr := &Manager{capabilities: mockCaps}
			err := mgr.validateSubdomainRequirement(context.Background(), tc.domain, tc.cluster)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "requires a subdomain label")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
