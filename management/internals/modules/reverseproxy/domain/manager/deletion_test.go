package manager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestDeleteDomain_ServiceDependencies(t *testing.T) {
	for _, tt := range []struct {
		name        string
		domainName  string
		serviceHost string
		accountID   string
		enabled     bool
		protected   bool
	}{
		{"exact", "example.com", "example.com", accountA, true, true},
		{"subdomain", "example.com", "deep.app.example.com", accountA, true, true},
		{"disabled", "example.com", "app.example.com", accountA, false, true},
		{"other account", "example.com", "app.example.com", accountB, true, true},
		{"case and trailing dot", "example.com", "APP.EXAMPLE.COM.", accountA, true, true},
		{"suffix boundary", "example.com", "notexample.com", accountA, true, false},
		{"literal underscore", "a_b.example.com", "app.a_b.example.com", accountA, true, true},
		{"underscore wildcard", "a_b.example.com", "app.axb.example.com", accountA, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			env := setupDomainTest(t)
			events := captureDomainEvents(env)
			d, err := env.store.CreateCustomDomain(ctx, accountA, tt.domainName, testCluster, true)
			require.NoError(t, err)
			svc := &rpservice.Service{
				ID: "dependent", AccountID: tt.accountID, Domain: tt.serviceHost,
				Enabled: tt.enabled, ProxyCluster: testCluster,
			}
			require.NoError(t, env.store.CreateService(ctx, svc))
			router := mux.NewRouter()
			RegisterEndpoints(router, env.manager)
			deleteDomain := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodDelete, "/domains/"+d.ID, nil)
				req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: accountA, UserId: accountAUser})
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				return response
			}

			response := deleteDomain()
			if tt.protected {
				require.Equal(t, http.StatusPreconditionFailed, response.Code, "dependent services must block deletion: %s", response.Body.String())
				assert.NotContains(t, response.Body.String(), tt.accountID, "the error must not reveal the service's account")
				assert.NotNil(t, storedDomain(t, env.store, accountA, d.Domain), "the namespace must remain reserved")
				assert.Empty(t, events.get(), "rejected deletion must not emit DomainDeleted")
				stored, err := env.store.GetServiceByID(ctx, nbstore.LockingStrengthNone, tt.accountID, svc.ID)
				require.NoError(t, err)
				assert.Equal(t, svc.Enabled, stored.Enabled, "rejected deletion must preserve the service")
				require.NoError(t, env.store.DeleteService(ctx, tt.accountID, svc.ID))
				response = deleteDomain()
			}
			require.Equal(t, http.StatusNoContent, response.Code, "deletion must succeed without dependencies: %s", response.Body.String())
			assert.Nil(t, storedDomain(t, env.store, accountA, d.Domain), "the registration must be deleted")
			captured := events.get()
			require.Len(t, captured, 1, "only successful deletion may emit an event")
			assert.Equal(t, activity.DomainDeleted, captured[0].Activity, "the event must describe the successful deletion")
		})
	}
}
