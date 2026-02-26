package manager

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integrations/extra_settings"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestInitializeServiceForCreate(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	t.Run("successful initialization without cluster deriver", func(t *testing.T) {
		mgr := &managerImpl{
			clusterDeriver: nil,
		}

		service := &reverseproxy.Service{
			Domain: "example.com",
			Auth:   reverseproxy.AuthConfig{},
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
		mgr := &managerImpl{
			clusterDeriver: nil,
		}

		service1 := &reverseproxy.Service{Domain: "test1.com", Auth: reverseproxy.AuthConfig{}}
		service2 := &reverseproxy.Service{Domain: "test2.com", Auth: reverseproxy.AuthConfig{}}

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
	accountID := "test-account"

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
					GetServiceByDomain(ctx, accountID, "available.com").
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
					GetServiceByDomain(ctx, accountID, "exists.com").
					Return(&reverseproxy.Service{ID: "existing-id", Domain: "exists.com"}, nil)
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
					GetServiceByDomain(ctx, accountID, "exists.com").
					Return(&reverseproxy.Service{ID: "service-123", Domain: "exists.com"}, nil)
			},
			expectedError: false,
		},
		{
			name:             "domain exists with different ID",
			domain:           "exists.com",
			excludeServiceID: "service-456",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, accountID, "exists.com").
					Return(&reverseproxy.Service{ID: "service-123", Domain: "exists.com"}, nil)
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
					GetServiceByDomain(ctx, accountID, "error.com").
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

			mgr := &managerImpl{}
			err := mgr.checkDomainAvailable(ctx, mockStore, accountID, tt.domain, tt.excludeServiceID)

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
	accountID := "test-account"

	t.Run("empty domain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, accountID, "").
			Return(nil, status.Errorf(status.NotFound, "not found"))

		mgr := &managerImpl{}
		err := mgr.checkDomainAvailable(ctx, mockStore, accountID, "", "")

		assert.NoError(t, err)
	})

	t.Run("empty exclude ID with existing service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, accountID, "test.com").
			Return(&reverseproxy.Service{ID: "some-id", Domain: "test.com"}, nil)

		mgr := &managerImpl{}
		err := mgr.checkDomainAvailable(ctx, mockStore, accountID, "test.com", "")

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
			GetServiceByDomain(ctx, accountID, "nil.com").
			Return(nil, nil)

		mgr := &managerImpl{}
		err := mgr.checkDomainAvailable(ctx, mockStore, accountID, "nil.com", "")

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
		service := &reverseproxy.Service{
			ID:      "service-123",
			Domain:  "new.com",
			Targets: []*reverseproxy.Target{},
		}

		// Mock ExecuteInTransaction to execute the function immediately
		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				// Create another mock for the transaction
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByDomain(ctx, accountID, "new.com").
					Return(nil, status.Errorf(status.NotFound, "not found"))
				txMock.EXPECT().
					CreateService(ctx, service).
					Return(nil)

				return fn(txMock)
			})

		mgr := &managerImpl{store: mockStore}
		err := mgr.persistNewService(ctx, accountID, service)

		assert.NoError(t, err)
	})

	t.Run("domain already exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		service := &reverseproxy.Service{
			ID:      "service-123",
			Domain:  "existing.com",
			Targets: []*reverseproxy.Target{},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByDomain(ctx, accountID, "existing.com").
					Return(&reverseproxy.Service{ID: "other-id", Domain: "existing.com"}, nil)

				return fn(txMock)
			})

		mgr := &managerImpl{store: mockStore}
		err := mgr.persistNewService(ctx, accountID, service)

		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())
	})
}
func TestPreserveExistingAuthSecrets(t *testing.T) {
	mgr := &managerImpl{}

	t.Run("preserve password when empty", func(t *testing.T) {
		existing := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "hashed-password",
				},
			},
		}

		updated := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, existing.Auth.PasswordAuth, updated.Auth.PasswordAuth)
	})

	t.Run("preserve pin when empty", func(t *testing.T) {
		existing := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PinAuth: &reverseproxy.PINAuthConfig{
					Enabled: true,
					Pin:     "hashed-pin",
				},
			},
		}

		updated := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PinAuth: &reverseproxy.PINAuthConfig{
					Enabled: true,
					Pin:     "",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, existing.Auth.PinAuth, updated.Auth.PinAuth)
	})

	t.Run("do not preserve when password is provided", func(t *testing.T) {
		existing := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "old-password",
				},
			},
		}

		updated := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
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
	mgr := &managerImpl{}

	existing := &reverseproxy.Service{
		Meta: reverseproxy.ServiceMeta{
			CertificateIssuedAt: func() *time.Time { t := time.Now(); return &t }(),
			Status:              "active",
		},
		SessionPrivateKey: "private-key",
		SessionPublicKey:  "public-key",
	}

	updated := &reverseproxy.Service{
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

	newEphemeralService := func() *reverseproxy.Service {
		return &reverseproxy.Service{
			ID:         serviceID,
			AccountID:  accountID,
			Name:       "test-service",
			Domain:     "test.example.com",
			Source:     reverseproxy.SourceEphemeral,
			SourcePeer: ownerPeerID,
		}
	}

	newPermanentService := func() *reverseproxy.Service {
		return &reverseproxy.Service{
			ID:        serviceID,
			AccountID: accountID,
			Name:      "api-service",
			Domain:    "api.example.com",
			Source:    reverseproxy.SourcePermanent,
		}
	}

	newProxyServer := func(t *testing.T) *nbgrpc.ProxyServiceServer {
		t.Helper()
		tokenStore := nbgrpc.NewOneTimeTokenStore(1 * time.Hour)
		srv := nbgrpc.NewProxyServiceServer(nil, tokenStore, nbgrpc.ProxyOIDCConfig{}, nil, nil)
		t.Cleanup(srv.Close)
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

		mgr := &managerImpl{
			store:           mockStore,
			accountManager:  mockAccountMgr,
			proxyGRPCServer: newProxyServer(t),
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

		mgr := &managerImpl{
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

		mgr := &managerImpl{
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

		mgr := &managerImpl{
			store:           mockStore,
			accountManager:  mockAccountMgr,
			proxyGRPCServer: newProxyServer(t),
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

		mgr := &managerImpl{
			store:           mockStore,
			accountManager:  mockAccountMgr,
			proxyGRPCServer: newProxyServer(t),
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

// noopExtraSettings is a minimal extra_settings.Manager for tests without external integrations.
type noopExtraSettings struct{}

func (n *noopExtraSettings) GetExtraSettings(_ context.Context, _ string) (*types.ExtraSettings, error) {
	return &types.ExtraSettings{}, nil
}

func (n *noopExtraSettings) UpdateExtraSettings(_ context.Context, _, _ string, _ *types.ExtraSettings) (bool, error) {
	return false, nil
}

var _ extra_settings.Manager = (*noopExtraSettings)(nil)

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
func setupIntegrationTest(t *testing.T) (*managerImpl, store.Store) {
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
	usersMgr := users.NewManager(testStore)
	settingsMgr := settings.NewManager(testStore, usersMgr, &noopExtraSettings{}, permsMgr, settings.IdpConfig{})

	var storedEvents []activity.Activity
	accountMgr := &mock_server.MockAccountManager{
		StoreEventFunc: func(_ context.Context, _, _, _ string, activityID activity.ActivityDescriber, _ map[string]any) {
			storedEvents = append(storedEvents, activityID.(activity.Activity))
		},
		UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		GetGroupByNameFunc: func(ctx context.Context, accountID, groupName string) (*types.Group, error) {
			return testStore.GetGroupByName(ctx, store.LockingStrengthNone, groupName, accountID)
		},
	}

	tokenStore := nbgrpc.NewOneTimeTokenStore(1 * time.Hour)
	proxySrv := nbgrpc.NewProxyServiceServer(nil, tokenStore, nbgrpc.ProxyOIDCConfig{}, nil, nil)
	t.Cleanup(proxySrv.Close)

	mgr := &managerImpl{
		store:              testStore,
		accountManager:     accountMgr,
		permissionsManager: permsMgr,
		settingsManager:    settingsMgr,
		proxyGRPCServer:    proxySrv,
		clusterDeriver: &testClusterDeriver{
			domains: []string{"test.netbird.io"},
		},
	}
	mgr.exposeTracker = &exposeTracker{manager: mgr}

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
		mgr := &managerImpl{store: mockStore}
		err := mgr.validateExposePermission(ctx, testAccountID, testPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get account settings")
	})
}

func TestCreateServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("creates service with random domain", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		req := &reverseproxy.ExposeServiceRequest{
			Port:     8080,
			Protocol: "http",
		}

		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ServiceName, "service name should be generated")
		assert.Contains(t, resp.Domain, "test.netbird.io", "domain should use cluster domain")
		assert.NotEmpty(t, resp.ServiceURL, "service URL should be set")

		// Verify service is persisted in store
		persisted, err := testStore.GetServiceByDomain(ctx, testAccountID, resp.Domain)
		require.NoError(t, err)
		assert.Equal(t, resp.Domain, persisted.Domain)
		assert.Equal(t, reverseproxy.SourceEphemeral, persisted.Source, "source should be ephemeral")
		assert.Equal(t, testPeerID, persisted.SourcePeer, "source peer should be set")
		assert.NotNil(t, persisted.Meta.LastRenewedAt, "last renewed should be set")
	})

	t.Run("creates service with custom domain", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		req := &reverseproxy.ExposeServiceRequest{
			Port:     80,
			Protocol: "http",
			Domain:   "example.com",
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

		req := &reverseproxy.ExposeServiceRequest{
			Port:     8080,
			Protocol: "http",
		}

		_, err = mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("validates request fields", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		req := &reverseproxy.ExposeServiceRequest{
			Port:     0,
			Protocol: "http",
		}

		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port")
	})
}

func TestExposeServiceRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		req     reverseproxy.ExposeServiceRequest
		wantErr string
	}{
		{
			name:    "valid http request",
			req:     reverseproxy.ExposeServiceRequest{Port: 8080, Protocol: "http"},
			wantErr: "",
		},
		{
			name:    "valid https request with pin",
			req:     reverseproxy.ExposeServiceRequest{Port: 443, Protocol: "https", Pin: "123456"},
			wantErr: "",
		},
		{
			name:    "port zero rejected",
			req:     reverseproxy.ExposeServiceRequest{Port: 0, Protocol: "http"},
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "negative port rejected",
			req:     reverseproxy.ExposeServiceRequest{Port: -1, Protocol: "http"},
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "port above 65535 rejected",
			req:     reverseproxy.ExposeServiceRequest{Port: 65536, Protocol: "http"},
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "unsupported protocol",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "tcp"},
			wantErr: "unsupported protocol",
		},
		{
			name:    "invalid pin format",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "http", Pin: "abc"},
			wantErr: "invalid pin",
		},
		{
			name:    "pin too short",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "http", Pin: "12345"},
			wantErr: "invalid pin",
		},
		{
			name:    "valid 6-digit pin",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "http", Pin: "000000"},
			wantErr: "",
		},
		{
			name:    "empty user group name",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "http", UserGroups: []string{"valid", ""}},
			wantErr: "user group name cannot be empty",
		},
		{
			name:    "invalid name prefix",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "http", NamePrefix: "INVALID"},
			wantErr: "invalid name prefix",
		},
		{
			name:    "valid name prefix",
			req:     reverseproxy.ExposeServiceRequest{Port: 80, Protocol: "http", NamePrefix: "my-service"},
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
		var req *reverseproxy.ExposeServiceRequest
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
		req := &reverseproxy.ExposeServiceRequest{
			Port:     8080,
			Protocol: "http",
		}
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)

		// Delete by domain using unexported method
		err = mgr.deleteServiceFromPeer(ctx, testAccountID, testPeerID, resp.Domain, false)
		require.NoError(t, err)

		// Verify service is deleted
		_, err = testStore.GetServiceByDomain(ctx, testAccountID, resp.Domain)
		require.Error(t, err, "service should be deleted")
	})

	t.Run("expire uses correct activity", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		req := &reverseproxy.ExposeServiceRequest{
			Port:     8080,
			Protocol: "http",
		}
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)

		err = mgr.deleteServiceFromPeer(ctx, testAccountID, testPeerID, resp.Domain, true)
		require.NoError(t, err)
	})
}

func TestStopServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("stops service by domain", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		req := &reverseproxy.ExposeServiceRequest{
			Port:     8080,
			Protocol: "http",
		}
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, req)
		require.NoError(t, err)

		err = mgr.StopServiceFromPeer(ctx, testAccountID, testPeerID, resp.Domain)
		require.NoError(t, err)

		_, err = testStore.GetServiceByDomain(ctx, testAccountID, resp.Domain)
		require.Error(t, err, "service should be deleted")
	})
}

func TestDeleteService_UntracksEphemeralExpose(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupIntegrationTest(t)

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
		Port:     8080,
		Protocol: "http",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, mgr.exposeTracker.CountPeerExposes(testPeerID), "expose should be tracked after create")

	// Look up the service by domain to get its store ID
	svc, err := mgr.store.GetServiceByDomain(ctx, testAccountID, resp.Domain)
	require.NoError(t, err)

	// Delete via the API path (user-initiated)
	err = mgr.DeleteService(ctx, testAccountID, testUserID, svc.ID)
	require.NoError(t, err)

	assert.Equal(t, 0, mgr.exposeTracker.CountPeerExposes(testPeerID), "expose should be untracked after API delete")

	// A new expose should succeed (not blocked by stale tracking)
	_, err = mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
		Port:     9090,
		Protocol: "http",
	})
	assert.NoError(t, err, "new expose should succeed after API delete cleared tracking")
}

func TestDeleteAllServices_UntracksEphemeralExposes(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupIntegrationTest(t)

	for i := range 3 {
		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
			Port:     8080 + i,
			Protocol: "http",
		})
		require.NoError(t, err)
	}

	assert.Equal(t, 3, mgr.exposeTracker.CountPeerExposes(testPeerID), "all exposes should be tracked")

	err := mgr.DeleteAllServices(ctx, testAccountID, testUserID)
	require.NoError(t, err)

	assert.Equal(t, 0, mgr.exposeTracker.CountPeerExposes(testPeerID), "all exposes should be untracked after DeleteAllServices")
}

func TestRenewServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("renews tracked expose", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &reverseproxy.ExposeServiceRequest{
			Port:     8080,
			Protocol: "http",
		})
		require.NoError(t, err)

		err = mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, resp.Domain)
		require.NoError(t, err)
	})

	t.Run("fails for untracked domain", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		err := mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, "nonexistent.com")
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
