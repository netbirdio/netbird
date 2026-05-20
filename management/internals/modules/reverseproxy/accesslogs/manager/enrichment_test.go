package manager

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestSaveAccessLog_EnrichesUserGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := store.NewMockStore(ctrl)

	user := &types.User{Id: "u1", AutoGroups: []string{"g1", "g2"}}
	mockStore.EXPECT().
		GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "u1").
		Return(user, nil)

	var captured *accesslogs.AccessLogEntry
	mockStore.EXPECT().
		CreateAccessLog(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, e *accesslogs.AccessLogEntry) error {
			captured = e
			return nil
		})

	m := &managerImpl{store: mockStore}
	entry := &accesslogs.AccessLogEntry{AccountID: "acc-1", UserId: "u1"}
	require.NoError(t, m.SaveAccessLog(context.Background(), entry))

	require.NotNil(t, captured, "CreateAccessLog must receive the entry")
	assert.Equal(t, []string{"g1", "g2"}, captured.UserGroups, "UserGroups should be hydrated from the user record")
}
