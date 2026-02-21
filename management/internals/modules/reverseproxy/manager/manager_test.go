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
			CertificateIssuedAt: time.Now(),
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
				txMock.EXPECT().
					GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
					Return(testPeer, nil)
				return fn(txMock)
			})

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
				txMock.EXPECT().
					GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
					Return(testPeer, nil)
				return fn(txMock)
			})

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
				txMock.EXPECT().
					GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
					Return(testPeer, nil)
				return fn(txMock)
			})

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
			Extra: &types.ExtraSettings{
				PeerExposeEnabled: true,
				PeerExposeGroups:  []string{testGroupID},
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

	return mgr, testStore
}

func TestValidateExposePermission(t *testing.T) {
	ctx := context.Background()

	t.Run("allowed when peer is in expose group", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)
		err := mgr.ValidateExposePermission(ctx, testAccountID, testPeerID)
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

		err = mgr.ValidateExposePermission(ctx, testAccountID, otherPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in an allowed expose group")
	})

	t.Run("denied when expose is disabled", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// Disable peer expose
		s, err := testStore.GetAccountSettings(ctx, store.LockingStrengthNone, testAccountID)
		require.NoError(t, err)
		s.Extra.PeerExposeEnabled = false
		err = testStore.SaveAccountSettings(ctx, testAccountID, s)
		require.NoError(t, err)

		err = mgr.ValidateExposePermission(ctx, testAccountID, testPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("disallowed when no groups configured", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		// Enable expose with empty groups — no groups configured means no peer is allowed
		s, err := testStore.GetAccountSettings(ctx, store.LockingStrengthNone, testAccountID)
		require.NoError(t, err)
		s.Extra.PeerExposeGroups = []string{}
		err = testStore.SaveAccountSettings(ctx, testAccountID, s)
		require.NoError(t, err)

		err = mgr.ValidateExposePermission(ctx, testAccountID, testPeerID)
		assert.Error(t, err)
	})

	t.Run("error when settings manager is nil", func(t *testing.T) {
		mgr := &managerImpl{settingsManager: nil}
		err := mgr.ValidateExposePermission(ctx, testAccountID, testPeerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "settings manager not available")
	})
}

func TestCreateServiceFromPeer(t *testing.T) {
	ctx := context.Background()

	t.Run("creates service with random domain", func(t *testing.T) {
		mgr, testStore := setupIntegrationTest(t)

		service := &reverseproxy.Service{
			Name:    "my-expose",
			Enabled: true,
			Targets: []*reverseproxy.Target{
				{
					AccountID:  testAccountID,
					Port:       8080,
					Protocol:   "http",
					TargetId:   testPeerID,
					TargetType: reverseproxy.TargetTypePeer,
					Enabled:    true,
				},
			},
		}

		created, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, service)
		require.NoError(t, err)
		assert.NotEmpty(t, created.ID, "service should have an ID")
		assert.Contains(t, created.Domain, "test.netbird.io", "domain should use cluster domain")
		assert.Equal(t, reverseproxy.SourceEphemeral, created.Source, "source should be ephemeral")
		assert.Equal(t, testPeerID, created.SourcePeer, "source peer should be set")
		assert.NotNil(t, created.Meta.LastRenewedAt, "last renewed should be set")

		// Verify service is persisted in store
		persisted, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, persisted.ID)
		assert.Equal(t, created.Domain, persisted.Domain)
	})

	t.Run("creates service with custom domain", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		service := &reverseproxy.Service{
			Name:    "custom",
			Domain:  "custom.example.com",
			Enabled: true,
			Targets: []*reverseproxy.Target{
				{
					AccountID:  testAccountID,
					Port:       80,
					Protocol:   "http",
					TargetId:   testPeerID,
					TargetType: reverseproxy.TargetTypePeer,
					Enabled:    true,
				},
			},
		}

		created, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, service)
		require.NoError(t, err)
		assert.Equal(t, "custom.example.com", created.Domain, "should keep the provided domain")
	})

	t.Run("replaces host by peer IP lookup", func(t *testing.T) {
		mgr, _ := setupIntegrationTest(t)

		service := &reverseproxy.Service{
			Name:    "lookup-test",
			Enabled: true,
			Targets: []*reverseproxy.Target{
				{
					AccountID:  testAccountID,
					Port:       3000,
					Protocol:   "http",
					TargetId:   testPeerID,
					TargetType: reverseproxy.TargetTypePeer,
					Enabled:    true,
				},
			},
		}

		created, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, service)
		require.NoError(t, err)
		require.Len(t, created.Targets, 1)
		assert.Equal(t, "100.64.0.1", created.Targets[0].Host, "host should be resolved to peer IP")
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
