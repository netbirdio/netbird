package http

import (
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/status"
)

func initPATTestData() *PATHandler {
	return &PATHandler{
		accountManager: &mock_server.MockAccountManager{

			AddPATToUserFunc: func(accountID string, userID string, pat *server.PersonalAccessToken) error {
				if nsGroupID == existingNSGroupID {
					return baseExistingNSGroup.Copy(), nil
				}
				return nil, status.Errorf(status.NotFound, "nameserver group with ID %s not found", nsGroupID)
			},

			GetAccountFromTokenFunc: func(_ jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return testingNSAccount, testingAccount.Users["test_user"], nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: testNSGroupAccountID,
				}
			}),
		),
	}
}
