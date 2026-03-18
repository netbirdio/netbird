package server

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/store"
)

func TestResolveDomains_FreshInstallUsesDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetAccountsCounter(gomock.Any()).Return(int64(0), nil)

	srv := NewServer(&Config{NbConfig: &nbconfig.Config{}})
	Inject[store.Store](srv, mockStore)

	srv.resolveDomains(context.Background())

	require.Equal(t, DefaultSelfHostedDomain, srv.dnsDomain)
	require.Equal(t, DefaultSelfHostedDomain, srv.mgmtSingleAccModeDomain)
}

func TestResolveDomains_ExistingInstallUsesPersistedDomain(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetAccountsCounter(gomock.Any()).Return(int64(1), nil)
	mockStore.EXPECT().GetAnyAccountID(gomock.Any()).Return("acc-1", nil)
	mockStore.EXPECT().GetAccountDomainAndCategory(gomock.Any(), store.LockingStrengthNone, "acc-1").Return("vpn.mycompany.com", "", nil)

	srv := NewServer(&Config{NbConfig: &nbconfig.Config{}})
	Inject[store.Store](srv, mockStore)

	srv.resolveDomains(context.Background())

	require.Equal(t, "vpn.mycompany.com", srv.dnsDomain)
	require.Equal(t, "vpn.mycompany.com", srv.mgmtSingleAccModeDomain)
}

func TestResolveDomains_StoreErrorFallsBackToDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetAccountsCounter(gomock.Any()).Return(int64(0), errors.New("db failed"))

	srv := NewServer(&Config{NbConfig: &nbconfig.Config{}})
	Inject[store.Store](srv, mockStore)

	srv.resolveDomains(context.Background())

	require.Equal(t, DefaultSelfHostedDomain, srv.dnsDomain)
	require.Equal(t, DefaultSelfHostedDomain, srv.mgmtSingleAccModeDomain)
}
