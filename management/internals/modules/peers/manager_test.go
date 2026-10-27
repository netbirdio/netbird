package peers

import (
	"context"
	"fmt"
	"testing"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/assert"

	"go.uber.org/mock/gomock"
)

func TestManager_GetPeersPaginated_HappyPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	// GetUserByUserID
	// GetAccountPeersPaginated
	// GetAccountSettings
	// GetUserPeers
	mockStore := store.NewMockStore(ctrl)
	// ValidateUserPermissions
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(&types.User{
			Id: "test-user",
		}, nil)
	permissionsManager.EXPECT().ValidateUserPermissions(gomock.Any(), gomock.Eq("test-account"), gomock.Eq("test-user"), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).Times(1).
		Return(true, context.Background(), nil)
	mockStore.EXPECT().GetAccountPeersPaginated(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account"),
		gomock.Eq(store.PaginationState{Page: 11, PageSize: 111}), gomock.Eq(store.PeerFilters{UserId: "test-user"}),
		gomock.Eq(store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})).Times(1).
		Return([]*peer.Peer{{ID: "test-peer"}}, 10, nil)

	peers, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, []*peer.Peer{{ID: "test-peer"}}, peers)
	assert.Equal(t, 10, total)
	assert.NoError(t, err)
}

func TestManager_GetPeersPaginated_GetUserWithError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(nil, fmt.Errorf("boom!"))

	_, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, 0, total)
	assert.ErrorContains(t, err, "boom!")
}

func TestManager_GetPeersPaginated_NoPermission(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(&types.User{
			Id: "test-user",
		}, nil)
	permissionsManager.EXPECT().ValidateUserPermissions(gomock.Any(), gomock.Eq("test-account"), gomock.Eq("test-user"), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).Times(1).
		Return(false, context.Background(), nil)
	mockStore.EXPECT().GetAccountSettings(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account")).Times(1).
		Return(&types.Settings{RegularUsersViewBlocked: false}, nil)
	mockStore.EXPECT().GetUserPeers(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account"), gomock.Eq("test-user")).Times(1).
		Return([]*peer.Peer{{ID: "test-peer"}}, nil)

	peers, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, []*peer.Peer{{ID: "test-peer"}}, peers)
	assert.Equal(t, 1, total)
	assert.NoError(t, err)
}

func TestManager_GetPeersPaginated_NoPermission_GetUserPeers_WithError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(&types.User{
			Id: "test-user",
		}, nil)
	permissionsManager.EXPECT().ValidateUserPermissions(gomock.Any(), gomock.Eq("test-account"), gomock.Eq("test-user"), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).Times(1).
		Return(false, context.Background(), nil)
	mockStore.EXPECT().GetAccountSettings(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account")).Times(1).
		Return(&types.Settings{RegularUsersViewBlocked: false}, nil)
	mockStore.EXPECT().GetUserPeers(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account"), gomock.Eq("test-user")).Times(1).
		Return(nil, fmt.Errorf("boom!"))

	_, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, 0, total)
	assert.ErrorContains(t, err, "boom!")
}

func TestManager_GetPeersPaginated_GetAccountSettings_WithError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(&types.User{
			Id: "test-user",
		}, nil)
	permissionsManager.EXPECT().ValidateUserPermissions(gomock.Any(), gomock.Eq("test-account"), gomock.Eq("test-user"), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).Times(1).
		Return(false, context.Background(), nil)
	mockStore.EXPECT().GetAccountSettings(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account")).Times(1).
		Return(nil, fmt.Errorf("boom!"))

	_, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, 0, total)
	assert.ErrorContains(t, err, "boom!")
}
func TestManager_GetPeersPaginated_NoPermission_User_IsRestrictable_ViewUnblocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(&types.User{
			Id:   "test-user",
			Role: types.UserRoleUser,
		}, nil)
	permissionsManager.EXPECT().ValidateUserPermissions(gomock.Any(), gomock.Eq("test-account"), gomock.Eq("test-user"), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).Times(1).
		Return(false, context.Background(), nil)
	mockStore.EXPECT().GetAccountSettings(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account")).Times(1).
		Return(&types.Settings{RegularUsersViewBlocked: false}, nil)
	mockStore.EXPECT().GetUserPeers(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account"), gomock.Eq("test-user")).Times(1).
		Return([]*peer.Peer{{ID: "test-peer"}}, nil)

	peers, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, []*peer.Peer{{ID: "test-peer"}}, peers)
	assert.Equal(t, 1, total)
	assert.NoError(t, err)
}

func TestManager_GetPeersPaginated_NoPermission_User_IsRestrictable_ViewBlocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	permissionsManager := permissions.NewMockManager(ctrl)

	m := NewManager(mockStore, permissionsManager)

	mockStore.EXPECT().GetUserByUserID(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-user")).Times(1).
		Return(&types.User{
			Id:   "test-user",
			Role: types.UserRoleUser,
		}, nil)
	permissionsManager.EXPECT().ValidateUserPermissions(gomock.Any(), gomock.Eq("test-account"), gomock.Eq("test-user"), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).Times(1).
		Return(false, context.Background(), nil)
	mockStore.EXPECT().GetAccountSettings(gomock.Any(), gomock.Eq(store.LockingStrengthNone), gomock.Eq("test-account")).Times(1).
		Return(&types.Settings{RegularUsersViewBlocked: true}, nil)

	peers, total, err := m.GetPeersPaginated(context.Background(), "test-account", "test-user",
		store.PaginationState{Page: 11, PageSize: 111}, store.PeerFilters{UserId: "test-user"},
		store.PeerSorting{Fields: []store.PeerSortingKey{{Field: store.PeerSortByName, Order: store.DescOrderBy}}})

	assert.Equal(t, make([]*peer.Peer, 0), peers)
	assert.Equal(t, 0, total)
	assert.NoError(t, err)
}

func TestManager_DeletePeers_IncrementsNetworkSerial(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	txStore := store.NewMockStore(ctrl)
	accountManager := account.NewMockManager(ctrl)
	networkMapController := network_map.NewMockController(ctrl)

	m := NewManager(mockStore, permissions.NewMockManager(ctrl)).(*managerImpl)
	m.accountManager = accountManager
	m.networkMapController = networkMapController

	ctx := context.Background()
	mockStore.EXPECT().GetAccountSettings(gomock.Any(), store.LockingStrengthNone, "test-account").Return(&types.Settings{}, nil)
	networkMapController.EXPECT().GetDNSDomain(gomock.Any()).Return("netbird.selfhosted")
	mockStore.EXPECT().ExecuteInTransaction(gomock.Any(), gomock.Any()).Times(2).
		DoAndReturn(func(_ context.Context, fn func(store.Store) error) error { return fn(txStore) })

	for _, id := range []string{"peer-1", "peer-2"} {
		txStore.EXPECT().GetPeerByID(gomock.Any(), store.LockingStrengthNone, "test-account", id).Return(&peer.Peer{ID: id, Status: &peer.PeerStatus{}}, nil)
		txStore.EXPECT().RemovePeerFromAllGroups(gomock.Any(), id).Return(nil)
		txStore.EXPECT().GetPolicyRulesByResourceID(gomock.Any(), store.LockingStrengthNone, "test-account", id).Return(nil, nil)
		txStore.EXPECT().DeletePeer(gomock.Any(), "test-account", id).Return(nil)
	}
	txStore.EXPECT().IncrementNetworkSerial(gomock.Any(), "test-account").Times(2).Return(nil)
	accountManager.EXPECT().StoreEvent(gomock.Any(), "test-user", gomock.Any(), "test-account", gomock.Any(), gomock.Any()).Times(2)
	accountManager.EXPECT().UpdateAccountPeers(gomock.Any(), "test-account", gomock.Any())

	assert.NoError(t, m.DeletePeers(ctx, "test-account", []string{"peer-1", "peer-2"}, "test-user", false))
}
