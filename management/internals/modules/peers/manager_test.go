package peers

import (
	"context"
	"fmt"
	"testing"

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
