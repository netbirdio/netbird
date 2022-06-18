package testdata

import (
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestAccountIssue(t *testing.T) {
	type initUserParams jwtclaims.AuthorizationClaims

	type test struct {
		name                        string
		inputClaims                 jwtclaims.AuthorizationClaims
		inputInitUserParams         jwtclaims.AuthorizationClaims
		inputUpdateAttrs            bool
		inputUpdateClaimAccount     bool
		testingFunc                 require.ComparisonAssertionFunc
		expectedMSG                 string
		expectedUserRole            server.UserRole
		expectedDomainCategory      string
		expectedPrimaryDomainStatus bool
		expectedCreatedBy           string
		expectedUsers               []string
	}

	var (
		publicDomain  = "public.com"
		privateDomain = "private.com"
		//unknownDomain = "unknown.com"
	)

	defaultInitAccount := jwtclaims.AuthorizationClaims{
		Domain: publicDomain,
		UserId: "defaultUser",
	}

	testCase6 := test{
		name: "Existing Account Id With Existing Reclassified Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain: privateDomain,
			UserId: "another",
			//DomainCategory: PrivateCategory,
		},
		inputUpdateClaimAccount:     true,
		inputInitUserParams:         defaultInitAccount,
		testingFunc:                 require.Equal,
		expectedMSG:                 "account IDs should match",
		expectedUserRole:            server.UserRoleAdmin,
		expectedDomainCategory:      server.PrivateCategory,
		expectedPrimaryDomainStatus: true,
		expectedCreatedBy:           defaultInitAccount.UserId,
		expectedUsers:               []string{defaultInitAccount.UserId},
	}
	for _, testCase := range []test{testCase6} {
		t.Run(testCase.name, func(t *testing.T) {
			manager, _ := createManager(t)

			//account1, _ := manager.GetAccountWithAuthorizationClaims(testCase.inputInitUserParams)
			//
			//account2, _ := manager.GetAccountWithAuthorizationClaims(testCase.inputClaims)

			//if account1.Id == account2.Id {
			//
			//	fs := manager.Store.(*server.FileStore)
			//	b, _ := json.Marshal(account2)
			//	a, _ := json.Marshal(account1)
			//	t.Log(string(a))
			//	t.Log(string(b))
			//	f, _ := json.Marshal(fs)
			//	t.Log(string(f))
			//}
			match := 0
			for i := 0; i < 10; i++ {
				var a1, a2 *server.Account
				wg := sync.WaitGroup{}
				wg.Add(2)
				go func() {
					s := xid.New().String()
					p := testCase.inputInitUserParams
					p.Domain = ""
					p.UserId = s
					a1, _ = manager.GetAccountWithAuthorizationClaims(p)
					wg.Done()
				}()
				go func() {
					s := xid.New().String()
					p := testCase.inputInitUserParams
					p.Domain = ""
					p.UserId = s
					a2, _ = manager.GetAccountWithAuthorizationClaims(p)
					wg.Done()
				}()

				wg.Wait()
				if a1.Id == a2.Id {
					match++
				}
				switch i {
				case 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000:
					t.Log(a1.Id, a2.Id)
				}
			}
			t.Log(match)
		})
	}
}

func createManager(t *testing.T) (*server.DefaultAccountManager, error) {
	store, err := createStore(t)
	if err != nil {
		return nil, err
	}
	return server.BuildManager(store, server.NewPeersUpdateManager(), nil)
}

func createStore(t *testing.T) (server.Store, error) {
	dataDir := t.TempDir()
	store, err := server.NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}
