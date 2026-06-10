package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestCreateTemporaryAccess_RejectsCallerWithoutPeersCreate verifies the
// defence-in-depth permission gate added to CreateTemporaryAccess: a user
// who cannot create peers must be turned away with 403 before any
// AccountManager call runs. Previously this endpoint relied entirely on
// SavePolicy/AddPeer's internal permission checks; the explicit gate
// makes sure a future refactor that bypasses one of those calls can't
// silently widen the endpoint's authority.
func TestCreateTemporaryAccess_RejectsCallerWithoutPeersCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	permMgr := permissions.NewMockManager(ctrl)

	// Caller lacks Peers.Create: handler must short-circuit before any
	// AccountManager interaction. We deliberately leave accountManager
	// nil so the test fails loudly if the handler tries to call it.
	permMgr.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(modules.Peers), gomock.Eq(operations.Create)).
		Return(false, context.Background(), nil).
		Times(1)

	h := &Handler{
		permissionsManager: permMgr,
	}

	pubKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	body, _ := json.Marshal(api.PeerTemporaryAccessRequest{
		Name:     "temp",
		Rules:    []string{"netbird-vnc"},
		WgPubKey: pubKey,
	})

	req := httptest.NewRequest(http.MethodPost, "/peers/peer-id/temporary-access", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"peerId": "peer-id"})
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    "regular_user",
		Domain:    "example.com",
		AccountId: "acct1",
	})

	rec := httptest.NewRecorder()
	h.CreateTemporaryAccess(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestCreateTemporaryAccess_RejectsCallerWithoutPoliciesCreate covers
// the second leg of the gate: a user with Peers.Create but not
// Policies.Create must still be refused. Catches a misconfiguration
// where one permission is granted broadly but the other isn't.
func TestCreateTemporaryAccess_RejectsCallerWithoutPoliciesCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	permMgr := permissions.NewMockManager(ctrl)

	permMgr.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(modules.Peers), gomock.Eq(operations.Create)).
		Return(true, context.Background(), nil).
		Times(1)
	permMgr.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(modules.Policies), gomock.Eq(operations.Create)).
		Return(false, context.Background(), nil).
		Times(1)

	h := &Handler{
		permissionsManager: permMgr,
	}

	body, _ := json.Marshal(api.PeerTemporaryAccessRequest{
		Name:  "temp",
		Rules: []string{"netbird-vnc"},
	})
	req := httptest.NewRequest(http.MethodPost, "/peers/peer-id/temporary-access", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"peerId": "peer-id"})
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    "regular_user",
		Domain:    "example.com",
		AccountId: "acct1",
	})

	rec := httptest.NewRecorder()
	h.CreateTemporaryAccess(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
